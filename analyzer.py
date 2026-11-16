import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

# 1. Padrão Regex para extrair campos de cada linha do log
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s-\s-\s'
    r'\[(?P<timestamp>.*?)\]\s'
    r'"(?P<method>\w+)\s(?P<endpoint>.*?)\sHTTP/.*?"\s'
    r'(?P<status>\d{3})\s(?P<size>\d+)'
)


def parse_log_line(line: str) -> dict | None:
    """Extrai dados estruturados de uma linha de log usando Regex."""
    match = LOG_PATTERN.match(line.strip())
    if match:
        return match.groupdict()
    return None


def analyze_logs(file_path: Path, brute_force_threshold: int = 5) -> dict:
    """Lê o arquivo de log linha por linha e consolida métricas de segurança e tráfego."""
    total_requests = 0
    malformed_lines = 0
    ip_counter = Counter()
    status_counter = Counter()
    endpoint_counter = Counter()
    failed_logins_by_ip = Counter()

    with file_path.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            parsed = parse_log_line(line)
            if not parsed:
                malformed_lines += 1
                continue

            total_requests += 1
            ip = parsed["ip"]
            status = parsed["status"]
            endpoint = parsed["endpoint"]

            ip_counter[ip] += 1
            status_counter[status] += 1
            endpoint_counter[endpoint] += 1

            # Detecta falhas de autenticação (HTTP 401 ou 403)
            if status in ("401", "403"):
                failed_logins_by_ip[ip] += 1

    # Identifica IPs que ultrapassaram o limite de falhas
    suspicious_ips = {
        ip: count
        for ip, count in failed_logins_by_ip.items()
        if count >= brute_force_threshold
    }

    return {
        "file": str(file_path),
        "total_requests": total_requests,
        "malformed_lines": malformed_lines,
        "top_ips": ip_counter.most_common(5),
        "status_codes": dict(status_counter),
        "top_endpoints": endpoint_counter.most_common(5),
        "suspicious_ips": suspicious_ips,
    }


def print_report(results: dict) -> None:
    """Exibe o relatório formatado no terminal."""
    print("\n" + "=" * 50)
    print(f"RELATÓRIO DE ANÁLISE DE LOGS: {results['file']}")
    print("=" * 50)
    print(f"Total de requisições válidas : {results['total_requests']}")
    print(f"Linhas ignoradas/malformadas : {results['malformed_lines']}")

    print("\n--- Códigos de Status HTTP ---")
    for status, count in sorted(results["status_codes"].items()):
        print(f"  HTTP {status}: {count} requisições")

    print("\n--- Top IPs mais ativos ---")
    for ip, count in results["top_ips"]:
        print(f"  {ip:<15} -> {count} requisições")

    print("\n--- Endpoints mais acessados ---")
    for endpoint, count in results["top_endpoints"]:
        print(f"  {endpoint:<20} -> {count} acessos")

    print("\n--- ALERTAS DE SEGURANÇA (Possível Força Bruta) ---")
    if results["suspicious_ips"]:
        for ip, count in results["suspicious_ips"].items():
            print(f"  [ALERTA] IP {ip} registrou {count} falhas de acesso (401/403)!")
    else:
        print("  Nenhuma atividade suspeita detectada acima do limite.")
    print("=" * 50 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Analisador de Logs Web em Linha de Comando."
    )
    parser.add_argument(
        "logfile",
        type=Path,
        help="Caminho para o arquivo de log a ser analisado."
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=5,
        help="Limite de falhas 401/403 para alertar força bruta (padrão: 5)."
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Salva o resultado em um arquivo JSON (opcional)."
    )

    args = parser.parse_args()

    if not args.logfile.exists() or not args.logfile.is_file():
        print(f"Erro: O arquivo '{args.logfile}' não foi encontrado.", file=sys.stderr)
        sys.exit(1)

    results = analyze_logs(args.logfile, brute_force_threshold=args.threshold)
    print_report(results)

    if args.output:
        with args.output.open("w", encoding="utf-8") as json_file:
            json.dump(results, json_file, indent=4, ensure_ascii=False)
        print(f"Relatório JSON salvo com sucesso em: {args.output}")


if __name__ == "__main__":
    main()