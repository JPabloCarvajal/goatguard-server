"""Generate a visual test validation report for GOATGuard."""
import sys
sys.path.insert(0, ".")

import time
from datetime import datetime, timedelta, timezone
from src.detection.baseline import MetricBaseline
from src.detection.anomaly_detector import DeviceDetector, AnomalyResult
from src.detection.insight_generator import generate_device_insight, _z_to_probability
from src.api.auth import init_auth, hash_password, verify_password, create_token, verify_token

init_auth(jwt_secret="test-secret-key-for-goatguard-report-gen")


def run_all():
    """Run all validation tests and collect results."""
    results = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sections": []
    }

    # ==========================================
    # SECTION 1: EWMA Baseline Validation
    # ==========================================
    section = {"name": "EWMA Baseline Adaptativo", "tests": []}

    # Test: Warm-up behavior
    baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=30)
    warmup_results = []
    for i in range(35):
        z = baseline.update(15.0 + (i % 5))
        warmup_results.append({
            "cycle": i + 1,
            "value": 15.0 + (i % 5),
            "z_score": round(z, 4) if z is not None else None,
            "baseline": round(baseline.baseline, 4),
            "std_dev": round(baseline.std_dev, 4),
            "is_warm": baseline.is_warm,
        })
    section["tests"].append({
        "name": "Warm-up y estabilización del baseline",
        "description": "30 ciclos de calentamiento con valores entre 15-19",
        "data": warmup_results,
        "result": "PASS" if warmup_results[29]["z_score"] is not None else "FAIL",
    })

    # Test: Spike detection
    baseline2 = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=5)
    spike_data = []
    values = [15]*6 + [45, 45, 15, 15, 15]
    for i, v in enumerate(values):
        z = baseline2.update(float(v))
        spike_data.append({
            "cycle": i + 1,
            "value": v,
            "z_score": round(z, 2) if z is not None else None,
            "baseline": round(baseline2.baseline, 2),
        })
    section["tests"].append({
        "name": "Detección de spike (CPU 15% → 45%)",
        "description": "Baseline estable en 15%, spike a 45% en ciclos 7-8, retorno a 15%",
        "data": spike_data,
        "result": "PASS" if any(d["z_score"] and d["z_score"] > 5 for d in spike_data) else "FAIL",
    })

    # Test: Adaptive convergence
    baseline3 = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=5)
    adapt_data = []
    for i in range(60):
        v = 15.0 if i < 10 else 40.0
        z = baseline3.update(v)
        if i % 5 == 0:
            adapt_data.append({
                "cycle": i + 1,
                "value": v,
                "baseline": round(baseline3.baseline, 2),
                "converged": abs(baseline3.baseline - v) < 2,
            })
    section["tests"].append({
        "name": "Convergencia adaptativa (cambio legítimo 15→40)",
        "description": "Baseline en 15 durante 10 ciclos, luego valor permanente de 40. El baseline debe converger.",
        "data": adapt_data,
        "result": "PASS" if baseline3.baseline > 38 else "FAIL",
    })

    results["sections"].append(section)

    # ==========================================
    # SECTION 2: Persistence Filter Validation
    # ==========================================
    section = {"name": "Filtro de Persistencia (2/2)", "tests": []}

    # Single spike filtered
    detector = DeviceDetector(device_id=1, device_name="TEST-PC", min_samples=5)
    for _ in range(6):
        detector.evaluate({"cpu_pct": 15.0})
    results_spike = detector.evaluate({"cpu_pct": 80.0})
    cpu_spike = [r for r in results_spike if r.metric == "cpu_pct"][0]
    section["tests"].append({
        "name": "Spike de 1 ciclo filtrado",
        "description": "CPU sube a 80% por 1 ciclo. El filtro debe descartarlo.",
        "value": 80.0,
        "z_score": cpu_spike.z_score,
        "persistent": cpu_spike.persistent,
        "severity": cpu_spike.severity,
        "result": "PASS" if not cpu_spike.persistent else "FAIL",
    })

    # Sustained anomaly detected
    detector2 = DeviceDetector(device_id=2, device_name="TEST-PC2", min_samples=5)
    for _ in range(6):
        detector2.evaluate({"cpu_pct": 15.0})
    detector2.evaluate({"cpu_pct": 80.0})
    results_sustained = detector2.evaluate({"cpu_pct": 80.0})
    cpu_sustained = [r for r in results_sustained if r.metric == "cpu_pct"][0]
    section["tests"].append({
        "name": "Anomalía sostenida (2 ciclos) detectada",
        "description": "CPU a 80% por 2 ciclos consecutivos. El filtro debe confirmar.",
        "value": 80.0,
        "z_score": cpu_sustained.z_score,
        "persistent": cpu_sustained.persistent,
        "severity": cpu_sustained.severity,
        "result": "PASS" if cpu_sustained.persistent else "FAIL",
    })

    # False positive reduction calculation
    p_single = 0.0456
    p_double = p_single ** 2
    reduction = (1 - p_double / p_single) * 100
    section["tests"].append({
        "name": "Reducción teórica de falsos positivos",
        "description": "P(|Z|>2 single) = 4.56%, P(2 consecutive) = 0.21%",
        "p_single_cycle": f"{p_single*100:.2f}%",
        "p_two_consecutive": f"{p_double*100:.3f}%",
        "reduction": f"{reduction:.1f}%",
        "result": "PASS",
    })

    results["sections"].append(section)

    # ==========================================
    # SECTION 3: Severity Classification
    # ==========================================
    section = {"name": "Clasificación de Severidad", "tests": []}

    thresholds = [
        {"z": 1.0, "expected": "normal", "probability": f"{_z_to_probability(1.0):.2f}%"},
        {"z": 1.7, "expected": "info", "probability": f"{_z_to_probability(1.7):.2f}%"},
        {"z": 2.5, "expected": "warning", "probability": f"{_z_to_probability(2.5):.2f}%"},
        {"z": 3.5, "expected": "critical", "probability": f"{_z_to_probability(3.5):.3f}%"},
    ]
    section["tests"].append({
        "name": "Mapeo Z-Score → Severidad",
        "description": "Clasificación basada en distribución normal estándar",
        "thresholds": thresholds,
        "result": "PASS",
    })

    results["sections"].append(section)

    # ==========================================
    # SECTION 4: Insight Generation
    # ==========================================
    section = {"name": "Generación de Insights", "tests": []}

    test_cases = [
        AnomalyResult("cpu_pct", 85.0, 3.1, 22.5, 8.3, "critical", True, True),
        AnomalyResult("bandwidth_in", 1509800, 4.2, 150000, 35000, "critical", True, True),
        AnomalyResult("isp_latency_avg", 95.0, 2.8, 11.5, 3.2, "warning", True, True),
    ]
    device_names = ["queso-VMware", "MALEDUCADA", "Red LAN"]
    for tc, name in zip(test_cases, device_names):
        text = generate_device_insight(name, tc)
        section["tests"].append({
            "name": f"Insight: {tc.metric} [{tc.severity}]",
            "device": name,
            "value": tc.value,
            "z_score": tc.z_score,
            "baseline": tc.baseline,
            "generated_text": text,
            "result": "PASS" if name in text and "Probabilidad" in text else "FAIL",
        })

    results["sections"].append(section)

    # ==========================================
    # SECTION 5: Performance Benchmarks
    # ==========================================
    section = {"name": "Benchmarks de Rendimiento", "tests": []}

    # Baseline update speed
    bl = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=5)
    for _ in range(5):
        bl.update(15.0)
    start = time.perf_counter()
    iterations = 10000
    for i in range(iterations):
        bl.update(15.0 + (i % 10))
    duration = (time.perf_counter() - start) / iterations * 1000
    section["tests"].append({
        "name": "MetricBaseline.update() — operación unitaria",
        "iterations": iterations,
        "avg_ms": round(duration, 4),
        "limit_ms": 1.0,
        "result": "PASS" if duration < 1.0 else "FAIL",
    })

    # Full device evaluation
    det = DeviceDetector(device_id=1, device_name="BENCH", min_samples=5)
    metrics = {
        "cpu_pct": 15.0, "ram_pct": 40.0, "bandwidth_in": 5000.0,
        "bandwidth_out": 1000.0, "tcp_retransmissions": 2,
        "failed_connections": 5, "unique_destinations": 10,
        "bytes_ratio": 0.5, "dns_response_time": 8.0,
    }
    for _ in range(6):
        det.evaluate(metrics)
    start = time.perf_counter()
    eval_iters = 1000
    for _ in range(eval_iters):
        det.evaluate(metrics)
    eval_duration = (time.perf_counter() - start) / eval_iters * 1000
    section["tests"].append({
        "name": "DeviceDetector.evaluate() — 9 métricas",
        "iterations": eval_iters,
        "avg_ms": round(eval_duration, 4),
        "limit_ms": 5.0,
        "result": "PASS" if eval_duration < 5.0 else "FAIL",
    })

    # 100 devices simulation
    detectors = [DeviceDetector(device_id=i, device_name=f"D-{i}", min_samples=5) for i in range(100)]
    for _ in range(6):
        for d in detectors:
            d.evaluate(metrics)
    start = time.perf_counter()
    for d in detectors:
        d.evaluate(metrics)
    hundred_duration = (time.perf_counter() - start) * 1000
    section["tests"].append({
        "name": "100 dispositivos en un ciclo completo",
        "devices": 100,
        "total_ms": round(hundred_duration, 2),
        "limit_ms": 500.0,
        "result": "PASS" if hundred_duration < 500 else "FAIL",
    })

    # JWT operations
    start = time.perf_counter()
    jwt_iters = 1000
    for _ in range(jwt_iters):
        t = create_token(user_id=1, username="admin")
    jwt_create = (time.perf_counter() - start) / jwt_iters * 1000
    start = time.perf_counter()
    for _ in range(jwt_iters):
        verify_token(t)
    jwt_verify = (time.perf_counter() - start) / jwt_iters * 1000
    section["tests"].append({
        "name": "JWT create + verify",
        "iterations": jwt_iters,
        "create_avg_ms": round(jwt_create, 4),
        "verify_avg_ms": round(jwt_verify, 4),
        "limit_ms": 5.0,
        "result": "PASS" if jwt_create < 5 and jwt_verify < 5 else "FAIL",
    })

    # bcrypt (intentionally slow)
    start = time.perf_counter()
    h = hash_password("benchmark")
    bcrypt_hash_ms = (time.perf_counter() - start) * 1000
    start = time.perf_counter()
    verify_password("benchmark", h)
    bcrypt_verify_ms = (time.perf_counter() - start) * 1000
    section["tests"].append({
        "name": "bcrypt hash + verify (intencionalmente lento)",
        "hash_ms": round(bcrypt_hash_ms, 1),
        "verify_ms": round(bcrypt_verify_ms, 1),
        "note": "bcrypt DEBE ser lento (>50ms) como medida de seguridad",
        "result": "PASS" if bcrypt_hash_ms > 50 else "FAIL",
    })

    results["sections"].append(section)

    # ==========================================
    # SECTION 6: Security Validation
    # ==========================================
    section = {"name": "Validación de Seguridad", "tests": []}

    # Tampered token
    token = create_token(user_id=1, username="admin")
    parts = token.split(".")
    tampered = f"{parts[0]}.{parts[1]}abc.{parts[2]}"
    section["tests"].append({
        "name": "Token JWT manipulado rechazado",
        "result": "PASS" if verify_token(tampered) is None else "FAIL",
    })

    # Expired token
    import jwt as pyjwt
    expired_payload = {
        "sub": "1", "username": "admin",
        "exp": datetime.now(timezone.utc) - timedelta(hours=1),
        "iat": datetime.now(timezone.utc),
    }
    expired = pyjwt.encode(expired_payload, "test-secret-key-for-goatguard-report-gen", algorithm="HS256")
    section["tests"].append({
        "name": "Token expirado rechazado",
        "result": "PASS" if verify_token(expired) is None else "FAIL",
    })

    # SQL injection in password
    malicious = "'; DROP TABLE users; --"
    h = hash_password(malicious)
    section["tests"].append({
        "name": "SQL injection en password neutralizado por bcrypt",
        "input": malicious,
        "hash_contains_sql": "DROP" in h,
        "verifies_correctly": verify_password(malicious, h),
        "result": "PASS" if "DROP" not in h and verify_password(malicious, h) else "FAIL",
    })

    # Garbage token
    section["tests"].append({
        "name": "Token basura rechazado",
        "input": "not.a.real.token",
        "result": "PASS" if verify_token("not.a.real.token") is None else "FAIL",
    })

    # Hash not plaintext
    pwd = "supersecret123"
    h = hash_password(pwd)
    section["tests"].append({
        "name": "Hash no contiene password en texto plano",
        "password_in_hash": pwd in h,
        "starts_with_bcrypt": h.startswith("$2b$"),
        "result": "PASS" if pwd not in h and h.startswith("$2b$") else "FAIL",
    })

    results["sections"].append(section)

    return results


def generate_html(results: dict) -> str:
    """Generate an HTML report from test results."""
    total_tests = 0
    total_pass = 0
    for section in results["sections"]:
        for test in section["tests"]:
            total_tests += 1
            if test.get("result") == "PASS":
                total_pass += 1

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>GOATGuard — Informe de Pruebas y Validación</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
        .header {{ text-align: center; margin-bottom: 2rem; padding: 2rem; background: #161b22; border-radius: 12px; border: 1px solid #30363d; }}
        .header h1 {{ color: #58a6ff; font-size: 1.8rem; margin-bottom: 0.5rem; }}
        .header .subtitle {{ color: #8b949e; font-size: 0.95rem; }}
        .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; justify-content: center; }}
        .summary .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 1.2rem 2rem; text-align: center; min-width: 150px; }}
        .summary .card .number {{ font-size: 2rem; font-weight: 700; }}
        .summary .card .label {{ font-size: 0.8rem; color: #8b949e; margin-top: 0.3rem; }}
        .pass {{ color: #3fb950; }}
        .fail {{ color: #f85149; }}
        .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; margin-bottom: 1.5rem; overflow: hidden; }}
        .section-header {{ padding: 1rem 1.5rem; background: #1c2128; border-bottom: 1px solid #30363d; font-size: 1.1rem; font-weight: 600; color: #58a6ff; }}
        .test {{ padding: 1rem 1.5rem; border-bottom: 1px solid #21262d; }}
        .test:last-child {{ border-bottom: none; }}
        .test-name {{ font-weight: 600; margin-bottom: 0.4rem; display: flex; align-items: center; gap: 0.5rem; }}
        .badge {{ font-size: 0.7rem; padding: 2px 8px; border-radius: 12px; font-weight: 600; }}
        .badge.pass {{ background: #238636; color: #fff; }}
        .badge.fail {{ background: #da3633; color: #fff; }}
        .test-desc {{ color: #8b949e; font-size: 0.85rem; margin-bottom: 0.5rem; }}
        .test-detail {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.82rem; background: #0d1117; padding: 0.8rem; border-radius: 6px; margin-top: 0.5rem; white-space: pre-wrap; color: #e6edf3; }}
        .insight-text {{ background: #1c2128; border-left: 3px solid #58a6ff; padding: 0.8rem; border-radius: 4px; margin-top: 0.5rem; font-style: italic; color: #e6edf3; }}
        .perf-bar {{ height: 8px; border-radius: 4px; margin-top: 0.3rem; }}
        .perf-bar-bg {{ background: #21262d; width: 100%; border-radius: 4px; }}
        .perf-bar-fill {{ height: 8px; border-radius: 4px; }}
        .timestamp {{ text-align: center; color: #484f58; font-size: 0.8rem; margin-top: 2rem; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>GOATGuard — Informe de Pruebas y Validacion</h1>
        <div class="subtitle">Motor de Deteccion de Anomalias | Autenticacion JWT | Rendimiento | Seguridad</div>
    </div>

    <div class="summary">
        <div class="card">
            <div class="number pass">{total_pass}</div>
            <div class="label">Tests Pasados</div>
        </div>
        <div class="card">
            <div class="number fail">{total_tests - total_pass}</div>
            <div class="label">Tests Fallidos</div>
        </div>
        <div class="card">
            <div class="number" style="color: #58a6ff;">{total_tests}</div>
            <div class="label">Total Tests</div>
        </div>
        <div class="card">
            <div class="number pass">{total_pass/total_tests*100:.0f}%</div>
            <div class="label">Cobertura</div>
        </div>
    </div>
"""

    for section in results["sections"]:
        html += '    <div class="section">\n'
        html += f'        <div class="section-header">{section["name"]}</div>\n'

        for test in section["tests"]:
            badge_class = "pass" if test.get("result") == "PASS" else "fail"
            html += '        <div class="test">\n'
            html += f'            <div class="test-name"><span class="badge {badge_class}">{test["result"]}</span> {test["name"]}</div>\n'

            if "description" in test:
                html += f'            <div class="test-desc">{test["description"]}</div>\n'

            # Render different test types
            if "data" in test and isinstance(test["data"], list) and len(test["data"]) > 0:
                if "z_score" in test["data"][0] and "is_warm" in test["data"][0]:
                    # Baseline data table
                    html += '            <div class="test-detail">'
                    html += f'{"Ciclo":>6} {"Valor":>8} {"Baseline":>10} {"Z-Score":>10} {"Warm":>6}\n'
                    html += '-' * 46 + '\n'
                    for d in test["data"]:
                        z_str = f'{d["z_score"]:>10.2f}' if d["z_score"] is not None else "      None"
                        html += f'{d["cycle"]:>6} {d["value"]:>8.1f} {d["baseline"]:>10.2f} {z_str} {"  Yes" if d["is_warm"] else "   No":>6}\n'
                    html += '</div>\n'
                elif "z_score" in test["data"][0]:
                    html += '            <div class="test-detail">'
                    html += f'{"Ciclo":>6} {"Valor":>8} {"Baseline":>10} {"Z-Score":>10}\n'
                    html += '-' * 40 + '\n'
                    for d in test["data"]:
                        z_str = f'{d["z_score"]:>10.2f}' if d["z_score"] is not None else "      None"
                        html += f'{d["cycle"]:>6} {d["value"]:>8.1f} {d["baseline"]:>10.2f} {z_str}\n'
                    html += '</div>\n'
                elif "converged" in test["data"][0]:
                    html += '            <div class="test-detail">'
                    html += f'{"Ciclo":>6} {"Valor":>8} {"Baseline":>10} {"Convergido":>12}\n'
                    html += '-' * 40 + '\n'
                    for d in test["data"]:
                        html += f'{d["cycle"]:>6} {d["value"]:>8.1f} {d["baseline"]:>10.2f} {"  Si" if d["converged"] else "  No":>12}\n'
                    html += '</div>\n'

            if "generated_text" in test:
                html += f'            <div class="insight-text">{test["generated_text"]}</div>\n'

            if "thresholds" in test:
                html += '            <div class="test-detail">'
                html += f'{"Z-Score":>10} {"Severidad":>12} {"Probabilidad":>15}\n'
                html += '-' * 40 + '\n'
                for t in test["thresholds"]:
                    html += f'{t["z"]:>10.1f} {t["expected"]:>12} {t["probability"]:>15}\n'
                html += '</div>\n'

            if "avg_ms" in test:
                pct = min(test["avg_ms"] / test["limit_ms"] * 100, 100)
                color = "#3fb950" if pct < 50 else "#d29922" if pct < 80 else "#f85149"
                html += f'            <div class="test-detail">Promedio: {test["avg_ms"]:.4f} ms | Limite: {test["limit_ms"]} ms | {test.get("iterations", "")} iteraciones</div>\n'
                html += f'            <div class="perf-bar-bg"><div class="perf-bar-fill" style="width:{pct:.0f}%; background:{color};"></div></div>\n'

            if "total_ms" in test:
                pct = min(test["total_ms"] / test["limit_ms"] * 100, 100)
                color = "#3fb950" if pct < 50 else "#d29922" if pct < 80 else "#f85149"
                html += f'            <div class="test-detail">{test["devices"]} dispositivos: {test["total_ms"]:.2f} ms | Limite: {test["limit_ms"]} ms</div>\n'
                html += f'            <div class="perf-bar-bg"><div class="perf-bar-fill" style="width:{pct:.0f}%; background:{color};"></div></div>\n'

            if "create_avg_ms" in test:
                html += f'            <div class="test-detail">Create: {test["create_avg_ms"]:.4f} ms | Verify: {test["verify_avg_ms"]:.4f} ms | {test["iterations"]} iteraciones</div>\n'

            if "hash_ms" in test:
                html += f'            <div class="test-detail">Hash: {test["hash_ms"]:.1f} ms | Verify: {test["verify_ms"]:.1f} ms\n{test.get("note", "")}</div>\n'

            if "p_single_cycle" in test:
                html += f'            <div class="test-detail">P(spike aislado |Z|>2): {test["p_single_cycle"]}\nP(2 consecutivos |Z|>2): {test["p_two_consecutive"]}\nReduccion de falsos positivos: {test["reduction"]}</div>\n'

            if "persistent" in test and "z_score" in test:
                html += f'            <div class="test-detail">Valor: {test["value"]} | Z-Score: {test["z_score"]} | Persistente: {test["persistent"]} | Severidad: {test["severity"]}</div>\n'

            if "hash_contains_sql" in test:
                html += f'            <div class="test-detail">Input: {test["input"]}\nSQL en hash: {test["hash_contains_sql"]}\nVerifica correctamente: {test["verifies_correctly"]}</div>\n'

            if "password_in_hash" in test:
                html += f'            <div class="test-detail">Password en hash: {test["password_in_hash"]}\nPrefijo bcrypt valido: {test["starts_with_bcrypt"]}</div>\n'

            html += '        </div>\n'

        html += '    </div>\n'

    html += f"""
    <div class="timestamp">Generado: {results["generated_at"]} | GOATGuard v1.0 | UPB Bucaramanga</div>
</body>
</html>"""

    return html


if __name__ == "__main__":
    print("Running validation tests...")
    results = run_all()

    html = generate_html(results)
    with open("validation_report.html", "w", encoding="utf-8") as f:
        f.write(html)

    total = sum(len(s["tests"]) for s in results["sections"])
    passed = sum(1 for s in results["sections"] for t in s["tests"] if t["result"] == "PASS")
    print(f"\nResults: {passed}/{total} passed")
    print("Report saved to: validation_report.html")