# EpiScan — Guide Utilisateur

## Synopsis

```
episcan-cli [options]
episcan-net  [options]
```

## Description

**EpiScan** est un outil d'analyse de sécurité qui combine :
- **Analyse statique de code** : détection de fonctions dangereuses, injections SQL, mauvaise cryptographie, débordements de buffer.
- **Scan réseau** : découverte de ports ouverts, identification de services, audit SSL/TLS.
- **Rapports** : JSON, HTML, Markdown avec score de sécurité et recommandations CVSS.

---

## episcan-cli — Analyseur de code

### Usage

```bash
episcan-cli --code <répertoire> [--report <fichier>]
episcan-cli --all-system [--report <fichier>]
episcan-cli --help
```

### Options

| Option | Description | Défaut |
|--------|-------------|--------|
| `--code <path>` | Répertoire à analyser | — |
| `--all-system` | Scanner tout le système depuis `/` | — |
| `--report <path>` | Fichier de rapport JSON de sortie | `report.json` |
| `--help` / `-h` | Afficher l'aide | — |

### Exemples

```bash
# Analyser un projet
episcan-cli --code ./mon_projet --report rapport.json

# Analyser tout le système (lent)
sudo episcan-cli --all-system --report /tmp/system_report.json

# Analyser le répertoire courant
episcan-cli --code .
```

### Catégories de détection

| Catégorie | Description | CWE |
|-----------|-------------|-----|
| `unsafe_func` | Fonctions C/C++ dangereuses (gets, strcpy…) | CWE-120 |
| `injection` | SQL, commande, path traversal | CWE-78, CWE-89, CWE-22 |
| `crypto` | Algo faibles (MD5, SHA1), secrets hardcodés | CWE-327, CWE-798 |
| `buffer` | Buffer overflow, use-after-free, double-free | CWE-120, CWE-416 |

### Format du rapport JSON

```json
{
  "scan_date": "2026-06-16T10:30:00Z",
  "target": "/mon/projet",
  "summary": {
    "critical": 2, "high": 5, "medium": 3, "low": 1,
    "total": 11, "security_score": 63.0,
    "scanned_files": 142
  },
  "findings": [
    {
      "id": "hardcoded-secret",
      "file": "src/auth.cpp",
      "line": 42,
      "severity": "critical",
      "cvss": 9.8,
      "category": "crypto",
      "message": "Secret potentiellement hardcodé dans le code source",
      "cwe": "CWE-798",
      "remediation": "Stocker les secrets dans des variables d'environnement",
      "code": "const char* password = \"s3cr3t\";"
    }
  ]
}
```

---

## episcan-net — Analyseur de trafic réseau

> Requiert `libpcap` et les droits `CAP_NET_RAW` (ou root) pour la capture live.

### Usage

```bash
sudo episcan-net --iface <interface> --duration <secondes>
episcan-net --pcap <fichier.pcap>
episcan-net --list-ifaces
```

### Options

| Option | Description | Défaut |
|--------|-------------|--------|
| `--iface <name>` | Interface réseau pour la capture live | `any` |
| `--duration <secs>` | Durée de capture en secondes | `30` |
| `--pcap <file>` | Analyser un fichier `.pcap` | — |
| `--report <path>` | Fichier de rapport JSON | `traffic_report.json` |
| `--max <n>` | Arrêter après n paquets (0 = illimité) | `0` |
| `--list-ifaces` | Lister les interfaces disponibles | — |
| `--help` / `-h` | Afficher l'aide | — |

### Exemples

```bash
# Capture live 60s sur eth0
sudo episcan-net --iface eth0 --duration 60 --report traffic.json

# Analyse d'un fichier PCAP
episcan-net --pcap capture.pcap --report traffic.json

# Lister les interfaces
episcan-net --list-ifaces
```

### Détections réseau

| Règle | Description | Sévérité |
|-------|-------------|----------|
| `log4shell-ldap` | CVE-2021-44228 : JNDI/LDAP injection | critical |
| `shellshock` | CVE-2014-6271 : Bash function injection | critical |
| `revshell-*` | Patterns de reverse shell TCP | high |
| `mimikatz-*` | Mimikatz credential dump | critical |
| `sqli-union-probe` | Sonde SQL injection UNION SELECT | medium |
| `port-scan` | Détection de scan de ports (SYN) | medium |
| `dns-tunneling` | Tunneling DNS heuristique | medium |
| `c2-known-port` | Trafic sur ports C2/RAT connus | medium |

---

## Niveaux de sévérité (CVSS v3.1)

| Sévérité | CVSS | Signification |
|----------|------|---------------|
| 🔴 Critical | 9.0–10.0 | Exploitation immédiate possible |
| 🟠 High | 7.0–8.9 | Risque élevé, corriger rapidement |
| 🟡 Medium | 4.0–6.9 | Risque modéré, planifier la correction |
| 🟢 Low | 0.1–3.9 | Risque faible, corriger si possible |

---

## Score de sécurité global

Le score part de 100 et décroît selon les findings :
- Critical : -15 points
- High : -8 points
- Medium : -3 points
- Low : -1 point

Score minimum : 0.

---

## Voir aussi

- [Architecture](architecture.md)
- [Guide développeur](dev_guide.md)
- Issues GitHub : https://github.com/AfyliX/EpiScan/issues
