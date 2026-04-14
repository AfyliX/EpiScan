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

### Analyse de code

- Détection de fonctions dangereuses (`UnsafeFunctionDetector`)
- Détection de patterns d'injection (`InjectionDetector`)
- Détection de cryptographie faible (`CryptoDetector`)
- Parsing de fichiers source (`CodeParser`)
- Agrégation des résultats (`VulnDetector`)

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

## Build (base)

Le dépôt contient déjà la structure CMake. Quand les fichiers de build seront finalisés :

```bash
mkdir -p build
cd build
cmake ..
cmake --build .
```

## Lancer les tests

```bash
cd build
ctest --output-on-failure
```

## Exemple d'utilisation (cible)

Commande visée à terme (exemple) :

```bash
./episcan --target 127.0.0.1 --ports 1-1024 --code ./src --report ./report.json
```

## Limites

- Détection basée sur signatures/patterns : possibles faux positifs/faux négatifs
- Couverture partielle des vulnérabilités avancées
- Ne remplace pas un EDR/antivirus ni un audit sécurité complet

## Roadmap suggérée

- [ ] Finaliser le binaire CLI principal
- [ ] Implémenter les modules `src/*` et exposer les options de scan
- [ ] Ajouter format de rapport JSON/HTML
- [ ] Étendre les tests unitaires et d'intégration
- [ ] Ajouter pipeline CI (build + tests)

## Éthique & légal

Utiliser uniquement sur des systèmes/réseaux que tu possèdes ou pour lesquels tu as une autorisation explicite.

## Licence

Voir le fichier `LICENSE`.

