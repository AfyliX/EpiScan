# EpiScan

EpiScan est un projet C++ orienté **analyse de sécurité locale et réseau**.
L'objectif est de fournir un scanner pédagogique capable de repérer des signaux de vulnérabilité dans du code, des services réseau et des configurations.

> ⚠️ Important : aucun outil ne peut détecter « littéralement tout » ce qui est malveillant sur une machine.
> EpiScan doit être vu comme un **outil d'aide au diagnostic**, pas comme une garantie de sécurité totale.

## Objectifs

- Détecter des patterns de vulnérabilités courants dans le code source
- Scanner des ports/services réseau pour identifier des surfaces d'attaque
- Enrichir les résultats avec une logique de score/sévérité
- Générer des rapports exploitables

## Fonctionnalités prévues

### Analyse de code (MVP actuel)

- Détection de patterns malveillants **haute confiance** (moins de faux positifs)
- Exemples : `rm -rf /`, `mkfs.`, `dd if=/dev/zero of=/dev/...`, `curl|sh`, `wget|bash`, `nc -e`, fork bomb
- Parsing récursif multi-langages sur fichiers texte orientés code/script
- Les commentaires sont ignorés pendant l'analyse (ligne/bloc sur syntaxes courantes)
- Une alerte est remontée seulement si le pattern apparaît dans un **contexte exécutable** (appel `system/exec/subprocess/...` ou script shell/PowerShell)
- Export des détections en JSON (fichier, ligne, sévérité, extrait)
- Scan multithread (utilise plusieurs cœurs CPU)
- Suivi de progression dans le terminal (`[scan] X/Y | current: <chemin>`)
- Interface SFML pour piloter le scan (target, report, all-system, résultats)
- Exclusions bruit par défaut : chemins `playwright`, chemins du projet `EpiScan`, `~/.config/Code/User/History`, `workspaceStorage`, `Trash`, `snap/code`, `/tmp/episcan*`, et fichiers `report*.json`/`episcan*.json`

### Analyse réseau (implémenté — branche `network`)

`episcan-net` capture le trafic réseau en temps réel (via **libpcap**) ou analyse un fichier `.pcap` existant et applique des règles de détection sur chaque paquet.

**Détections implémentées :**

| Règle | Sévérité | Description |
|---|---|---|
| Log4Shell CVE-2021-44228 (ldap/rmi/dns + variante obfusquée) | critical | `${jndi:…}` dans tout payload HTTP |
| ShellShock CVE-2014-6271 | critical | `() { :;};` dans les headers HTTP/CGI |
| Reverse shell bash, python, perl, ruby, nc, socat, php | high | Patterns string dans payload TCP |
| PHP webshell (`eval`/`assert` + `base64_decode`) | high | Injection de code côté serveur |
| Mimikatz (`sekurlsa`, `lsadump`, `kerberos::golden`) | critical | Dump de credentials en clair dans le trafic |
| Cobalt Strike beacon | critical | Chaîne `cobaltstrike` en clair |
| Injection SQL (`UNION SELECT`, `DROP TABLE`) | medium | Probes dans payload HTTP |
| Injection de commandes (`curl\|sh`, `wget\|sh`) | high | Payload HTTP |
| Credentials HTTP en clair (`password=` sur port 80) | medium | Formulaire non chiffré |
| Port scan | medium | Source SYN vers ≥ 20 ports distincts |
| DNS tunnelling | medium | Label DNS > 52 caractères (heuristique) |
| Trafic sur ports C2/RAT connus (4444, 1234, 6666…) | medium | Connexion TCP suspecte |

**Rapport JSON** généré avec : ruleId, sévérité, src/dst IP:port, protocole, extrait de payload, timestamp.

### Core

- Gestion de configuration (`Config`)
- Modèle de vulnérabilités (`Vulnerability`, `Severity`)
- Génération de rapports (`Report`)

## Structure du projet

```text
include/
	analyzer/
	core/
	network/
		TrafficAnalyzer.hpp   ← API analyse trafic
src/
	analyzer/
	core/
	network/
		TrafficAnalyzer.cpp   ← implémentation libpcap
	cli_main.cpp              ← episcan-cli
	gui_main.cpp              ← episcan (SFML)
	net_main.cpp              ← episcan-net
data/
	common_ports.json
	cve_database.json
	config_example.json
cmake/
	FindLibPCAP.cmake         ← détection libpcap
scripts/
	smoke_test.sh
	gen_test_pcap.py          ← générateur de pcap de test
tests/
docs/
```

## Prérequis

- Linux
- CMake (>= 3.16 recommandé)
- Compilateur C++17 (g++ ou clang++)
- **libpcap-dev** (pour `episcan-net`) : `sudo apt install libpcap-dev`
- SFML 2.5 (optionnel, pour l'interface graphique) : `sudo apt install libsfml-dev`
- Conan (optionnel, selon ton setup dépendances)

## Build

Build recommandé via CMake :

```bash
mkdir -p build
cd build
cmake ..
cmake --build .
```

Notes :
- `episcan` = interface SFML (antivirus-like)
- `episcan-cli` = exécutable terminal/script
- `episcan-net` = analyse de trafic réseau (nécessite libpcap-dev)
- si SFML n'est pas installé, `episcan` bascule automatiquement en mode CLI
- si libpcap n'est pas installé, `episcan-net` n'est pas compilé (avertissement CMake)

## Lancer un smoke test

```bash
./scripts/smoke_test.sh
```

## Exemple d'utilisation (MVP actuel)

```bash
./build/episcan

# mode CLI explicite
./build/episcan-cli --code ./src --report ./build/report.json

# format positionnel également supporté
./build/episcan-cli ./src --report ./build/report.json

# scanner tout le PC (Linux)
./build/episcan-cli --all-system --report ./build/full_system_report.json
```

Notes pour `--all-system` :
- le scan peut être long selon la machine
- certains chemins système spéciaux sont ignorés (`/proc`, `/sys`, `/dev`, `/run`)
- selon les permissions, il peut être utile d'exécuter avec des droits élevés

## Utilisation — Analyse de trafic réseau (`episcan-net`)

### Live capture (nécessite root ou CAP_NET_RAW)

```bash
# Capturer 60 secondes sur wlo1
sudo /chemin/vers/build/episcan-net --iface wlo1 --duration 60 --report traffic.json

# Ou donner la capability pour éviter sudo à chaque fois
sudo setcap cap_net_raw,cap_net_admin=eip ./build/episcan-net
./build/episcan-net --iface wlo1 --duration 60 --report traffic.json
```

### Analyse d'un fichier .pcap (sans privilèges)

```bash
./build/episcan-net --pcap capture.pcap --report results.json
```

### Lister les interfaces disponibles

```bash
./build/episcan-net --list-ifaces
```

### Générer un pcap de test (toutes les règles)

```bash
# Génère un fichier pcap avec 27 attaques simulées
python3 scripts/gen_test_pcap.py /tmp/test_attacks.pcap

# Analyser le résultat
./build/episcan-net --pcap /tmp/test_attacks.pcap --report /tmp/test_report.json
# → 34 findings : Log4Shell, ShellShock, reverse shells, Mimikatz, port scan...
```

## Limites

- Détection basée sur signatures/patterns : possibles faux positifs/faux négatifs
- Couverture partielle des vulnérabilités avancées
- Ne remplace pas un EDR/antivirus ni un audit sécurité complet
- N'analyse pas les binaires exécutables dans ce MVP (uniquement les fichiers texte)
- Le mode haute confiance peut rater certains cas ambigus pour éviter le bruit excessif

## Roadmap suggérée

- [x] Finaliser un binaire CLI principal MVP
- [x] Analyse de trafic réseau temps réel avec libpcap (`episcan-net`)
- [x] Détection Log4Shell, ShellShock, reverse shells, Mimikatz, Cobalt Strike…
- [x] Générateur de pcap de test (`scripts/gen_test_pcap.py`)
- [ ] Extraire la logique de détection vers `src/analyzer/*`
- [ ] Implémenter les modules Core (Vulnerability, Report, Config, Severity)
- [ ] PortScanner, ServiceDetector, BannerGrabber (module réseau actif)
- [ ] Ajouter format de rapport JSON/HTML
- [ ] Étendre les tests unitaires et d'intégration
- [ ] Ajouter pipeline CI (build + tests)

## Éthique & légal

Utiliser uniquement sur des systèmes/réseaux que tu possèdes ou pour lesquels tu as une autorisation explicite.

## Licence

Voir le fichier `LICENSE`.

