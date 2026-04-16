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

### Analyse réseau

- Scan de ports (`PortScanner`)
- Détection de services (`ServiceDetector`)
- Récupération de bannières (`BannerGrabber`)
- Corrélation vulnérabilités/service (`NetworkvulAnalyzer`)

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
src/
	analyzer/
	core/
	network/
data/
	common_ports.json
	cve_database.json
	config_example.json
tests/
docs/
```

## Prérequis

- Linux
- CMake (>= 3.16 recommandé)
- Compilateur C++17 (g++ ou clang++)
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
- si SFML n'est pas installé, `episcan` bascule automatiquement en mode CLI

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

## Limites

- Détection basée sur signatures/patterns : possibles faux positifs/faux négatifs
- Couverture partielle des vulnérabilités avancées
- Ne remplace pas un EDR/antivirus ni un audit sécurité complet
- N'analyse pas les binaires exécutables dans ce MVP (uniquement les fichiers texte)
- Le mode haute confiance peut rater certains cas ambigus pour éviter le bruit excessif

## Roadmap suggérée

- [x] Finaliser un binaire CLI principal MVP
- [ ] Extraire la logique de détection vers `src/analyzer/*`
- [ ] Ajouter format de rapport JSON/HTML
- [ ] Étendre les tests unitaires et d'intégration
- [ ] Ajouter pipeline CI (build + tests)

## Éthique & légal

Utiliser uniquement sur des systèmes/réseaux que tu possèdes ou pour lesquels tu as une autorisation explicite.

## Licence

Voir le fichier `LICENSE`.

