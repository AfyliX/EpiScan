#!/bin/bash

# ╔══════════════════════════════════════════════════════════════╗
# ║         EpiScan — Script Final Tout-en-Un                   ║
# ║  Crée issues + Project + Mandays + Assignees S1/S2          ║
# ╚══════════════════════════════════════════════════════════════╝

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC}  $1"; }
log_success() { echo -e "${GREEN}[✓]${NC}    $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }
log_step()    { echo -e "\n${CYAN}${BOLD}▶ $1${NC}"; }

# ─────────────────────────────────────────────
#  CONFIGURATION — MODIFIE CES 5 LIGNES
# ─────────────────────────────────────────────
GITHUB_USERNAME="afylix"      # owner du repo
REPO_NAME="EpiScan"           # nom exact du repo
PROJECT_NUMBER="2"            # numéro dans l'URL github.com/users/.../projects/2
STUDENT1=""                   # username GitHub S1 (module réseau)
STUDENT2=""                   # username GitHub S2 (analyse de code)

REPO="${GITHUB_USERNAME}/${REPO_NAME}"

# ─────────────────────────────────────────────
#  BANNIÈRE
# ─────────────────────────────────────────────
echo -e "${CYAN}"
cat << 'EOF'
 ███████╗██████╗ ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔════╝██╔══██╗██║██╔════╝██╔════╝██╔══██╗████╗  ██║
 █████╗  ██████╔╝██║███████╗██║     ███████║██╔██╗ ██║
 ██╔══╝  ██╔═══╝ ██║╚════██║██║     ██╔══██║██║╚██╗██║
 ███████╗██║     ██║███████║╚██████╗██║  ██║██║ ╚████║
 ╚══════╝╚═╝     ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    Script Final — Issues + Mandays + Assignees
EOF
echo -e "${NC}"

# ─────────────────────────────────────────────
#  PRÉREQUIS
# ─────────────────────────────────────────────
log_step "Vérification des prérequis"

command -v gh >/dev/null 2>&1 || log_error "gh CLI non installé → https://cli.github.com"
gh auth status >/dev/null 2>&1 || { log_warn "Non connecté..."; gh auth login; }
log_success "gh CLI : $(gh --version | head -1)"

# Saisie interactive des usernames si vides
if [ -z "$STUDENT1" ]; then
    read -rp "$(echo -e "${YELLOW}Username GitHub S1 (module réseau) : ${NC}")" STUDENT1
fi
if [ -z "$STUDENT2" ]; then
    read -rp "$(echo -e "${YELLOW}Username GitHub S2 (analyse de code) : ${NC}")" STUDENT2
fi
[ -z "$STUDENT1" ] && log_error "Username S1 requis"
[ -z "$STUDENT2" ] && log_error "Username S2 requis"

log_success "S1 = ${STUDENT1}  |  S2 = ${STUDENT2}"
gh repo view "$REPO" >/dev/null 2>&1 || log_error "Repo '$REPO' introuvable"

# ─────────────────────────────────────────────
#  PROJECT ID
# ─────────────────────────────────────────────
log_step "Récupération du Project ID"

PROJECT_ID=$(gh api graphql -f query="
query {
  user(login: \"${GITHUB_USERNAME}\") {
    projectV2(number: ${PROJECT_NUMBER}) { id }
  }
}" --jq '.data.user.projectV2.id' 2>/dev/null || echo "")

if [ -z "$PROJECT_ID" ]; then
    PROJECT_ID=$(gh api graphql -f query="
query {
  organization(login: \"${GITHUB_USERNAME}\") {
    projectV2(number: ${PROJECT_NUMBER}) { id }
  }
}" --jq '.data.organization.projectV2.id' 2>/dev/null || echo "")
fi

[ -z "$PROJECT_ID" ] && log_error "Project #${PROJECT_NUMBER} introuvable. Vérifie PROJECT_NUMBER."
log_success "Project ID : ${PROJECT_ID}"

# ─────────────────────────────────────────────
#  LABELS
# ─────────────────────────────────────────────
log_step "Création des labels"

create_label() {
    gh label create "$1" --color "$2" --description "$3" \
       --repo "$REPO" --force 2>/dev/null \
    && log_success "Label: $1" || log_warn "Label '$1' déjà existant"
}

create_label "feature"           "1f6feb" "Nouvelle fonctionnalité"
create_label "security"          "da3633" "Vulnérabilité ou audit sécurité"
create_label "testing"           "238636" "Tests unitaires / intégration"
create_label "docs"              "6e7681" "Documentation"
create_label "infra"             "9e6a03" "Build, CI, configuration"
create_label "perf"              "8957e5" "Performance et optimisation"
create_label "priority:critical" "b60205" "Priorité critique"
create_label "priority:high"     "e4e669" "Priorité haute"
create_label "priority:medium"   "0075ca" "Priorité moyenne"
create_label "priority:low"      "cfd3d7" "Priorité basse"

# ─────────────────────────────────────────────
#  CHAMP MANDAYS
# ─────────────────────────────────────────────
log_step "Champ Mandays dans le Project"

MANDAYS_FIELD_ID=$(gh api graphql -f query="
query {
  user(login: \"${GITHUB_USERNAME}\") {
    projectV2(number: ${PROJECT_NUMBER}) {
      fields(first: 30) {
        nodes {
          ... on ProjectV2Field { id name }
        }
      }
    }
  }
}" --jq '.data.user.projectV2.fields.nodes[] | select(.name == "Mandays") | .id' 2>/dev/null || echo "")

if [ -z "$MANDAYS_FIELD_ID" ]; then
    MANDAYS_FIELD_ID=$(gh api graphql -f query="
mutation {
  createProjectV2Field(input: {
    projectId: \"${PROJECT_ID}\"
    dataType: NUMBER
    name: \"Mandays\"
  }) {
    projectV2Field { ... on ProjectV2Field { id } }
  }
}" --jq '.data.createProjectV2Field.projectV2Field.id' 2>/dev/null || echo "")
    [ -n "$MANDAYS_FIELD_ID" ] \
        && log_success "Champ Mandays créé : ${MANDAYS_FIELD_ID}" \
        || log_warn "Impossible de créer le champ Mandays"
else
    log_success "Champ Mandays existant : ${MANDAYS_FIELD_ID}"
fi

# ─────────────────────────────────────────────
#  FONCTION PRINCIPALE
#  add_task TITLE BODY LABELS MANDAYS ASSIGNEES
#  ASSIGNEES : "S1" | "S2" | "BOTH"
# ─────────────────────────────────────────────
add_task() {
    local title="$1"
    local body="$2"
    local labels="$3"
    local mandays="$4"
    local who="$5"     # S1 | S2 | BOTH

    # Résoudre l'assignee
    local assignees=""
    case "$who" in
        S1)   assignees="$STUDENT1" ;;
        S2)   assignees="$STUDENT2" ;;
        BOTH) assignees="${STUDENT1},${STUDENT2}" ;;
    esac

    log_info "$(printf '%-52s' "$title") [${mandays}j → ${who}]"

    # --- Créer l'issue (3 tentatives) ---
    local attempt=0
    local issue_url=""
    while [ $attempt -lt 3 ]; do
        issue_url=$(gh issue create \
            --repo "$REPO" \
            --title "$title" \
            --body "$body" \
            --label "$labels" \
            --assignee "$assignees" \
            2>/dev/null) && break
        attempt=$((attempt+1))
        sleep 3
    done

    if [ -z "$issue_url" ]; then
        log_warn "Échec création : $title"
        return
    fi

    local issue_num
    issue_num=$(echo "$issue_url" | grep -oE '[0-9]+$')

    # --- Node ID (3 tentatives) ---
    attempt=0
    local node_id=""
    while [ $attempt -lt 3 ]; do
        node_id=$(gh api "repos/${REPO}/issues/${issue_num}" \
            --jq '.node_id' 2>/dev/null) && break
        attempt=$((attempt+1))
        sleep 3
    done

    # --- Ajouter au Project ---
    attempt=0
    local item_id=""
    while [ $attempt -lt 3 ]; do
        item_id=$(gh api graphql -f query="
mutation {
  addProjectV2ItemById(input: {
    projectId: \"${PROJECT_ID}\"
    contentId: \"${node_id}\"
  }) {
    item { id }
  }
}" --jq '.data.addProjectV2ItemById.item.id' 2>/dev/null) && break
        attempt=$((attempt+1))
        sleep 3
    done

    if [ -z "$item_id" ]; then
        log_warn "#${issue_num} créée mais non ajoutée au Project"
        return
    fi

    # --- Setter Mandays ---
    if [ -n "$MANDAYS_FIELD_ID" ]; then
        attempt=0
        while [ $attempt -lt 3 ]; do
            gh api graphql -f query="
mutation {
  updateProjectV2ItemFieldValue(input: {
    projectId: \"${PROJECT_ID}\"
    itemId: \"${item_id}\"
    fieldId: \"${MANDAYS_FIELD_ID}\"
    value: { number: ${mandays} }
  }) {
    projectV2Item { id }
  }
}" >/dev/null 2>&1 && break
            attempt=$((attempt+1))
            sleep 3
        done
    fi

    log_success "#${issue_num} — ${title} → ${mandays}j / ${who}"
    sleep 1
}

# ══════════════════════════════════════════════
#  TOUTES LES TÂCHES
# ══════════════════════════════════════════════
log_step "Création des issues EpiScan"

# ── INFRASTRUCTURE ───────────────────────────
add_task \
"Setup CMake + Conan dependencies" \
"## Objectif
Configurer le système de build CMake et le gestionnaire de dépendances Conan.

## Tâches
- [ ] Créer \`CMakeLists.txt\` avec les targets principaux
- [ ] Configurer \`conanfile.txt\` avec toutes les dépendances
- [ ] Lier Boost.Asio, OpenSSL, nlohmann/json, CLI11
- [ ] Vérifier la compilation sur Linux

## Dépendances
\`\`\`
Boost.Asio 1.83+   |   OpenSSL 3.1+
nlohmann/json 3.11+  |  CLI11 2.3+
Google Test 1.14+
\`\`\`" \
"infra,priority:high" "1" "S1"

add_task \
"Architecture modulaire du projet" \
"## Objectif
Définir et implémenter la structure de dossiers et l'architecture des modules.

## Structure cible
\`\`\`
src/
  network/      # Module réseau   → S1
  analyzer/     # Analyse de code → S2
  reporting/    # Rapports        → S1 + S2
  core/         # Utilitaires communs
include/
tests/
docs/
\`\`\`

## Tâches
- [ ] Créer la structure de dossiers
- [ ] Définir les interfaces entre modules
- [ ] Mettre en place les namespaces C++20
- [ ] Documenter l'architecture (diagramme)" \
"infra,priority:high" "1" "BOTH"

add_task \
"Intégration Google Test framework" \
"## Objectif
Mettre en place le framework de tests unitaires Google Test.

## Tâches
- [ ] Configurer GTest via Conan
- [ ] Créer le target CMake \`episcan_tests\`
- [ ] Ajouter les premiers tests smoke
- [ ] Configurer \`ctest\` pour l'exécution automatique" \
"testing,infra,priority:medium" "1" "S2"

# ── MODULE RÉSEAU (S1) ───────────────────────
add_task \
"Scanner de ports parallèle avec Boost.Asio" \
"## Objectif
Implémenter un scanner de ports TCP/UDP haute performance avec détection parallèle.

## Spécifications
- Ranges de ports : 1-1024, 80,443,8080
- Détection TCP connect avec timeout configurable
- Pool de threads : nb_cpu × 2 par défaut
- Résultats triés par port

## Interface
\`\`\`cpp
class PortScanner {
    ScanResult scan(const std::string& target,
                    PortRange range,
                    ScanConfig cfg);
};
\`\`\`

## Estimation : 3 mandays" \
"feature,priority:critical" "3" "S1"

add_task \
"Banner grabbing pour identification de services" \
"## Objectif
Identifier les services réseau via leurs banners (HTTP, FTP, SSH, SMTP...).

## Tâches
- [ ] Connexion TCP et lecture du banner initial
- [ ] Requêtes sondes par protocole
- [ ] Base de signatures de services
- [ ] Extraction de version depuis le banner

## Sortie
\`\`\`json
{ \"port\": 22, \"service\": \"ssh\", \"version\": \"OpenSSH 8.9\" }
\`\`\`

## Estimation : 2 mandays" \
"feature,priority:medium" "2" "S1"

add_task \
"Comparaison avec base CVE pour versions vulnérables" \
"## Objectif
Croiser les versions détectées avec la base NVD/CVE.

## Tâches
- [ ] Intégration API NVD (nvd.nist.gov/developers)
- [ ] Parser CPE depuis les services détectés
- [ ] Requêter les CVE par CPE + version
- [ ] Filtrer par score CVSS (seuil configurable)
- [ ] Cache local JSON des résultats

## Estimation : 3 mandays" \
"feature,security,priority:high" "3" "S1"

add_task \
"Audit SSL/TLS — détection de protocoles faibles" \
"## Objectif
Auditer la configuration SSL/TLS et détecter les configurations non sécurisées.

## Vérifications
- [ ] Protocoles dépréciés : SSLv2, SSLv3, TLSv1.0, TLSv1.1
- [ ] Chiffrements faibles : RC4, DES, 3DES, NULL
- [ ] Certificat expiré ou auto-signé
- [ ] HSTS manquant
- [ ] Heartbleed (CVE-2014-0160)

## Estimation : 2 mandays" \
"security,priority:critical" "2" "S1"

add_task \
"Support IPv6 dans le scanner réseau" \
"## Objectif
Étendre le scanner pour les adresses et plages IPv6.

## Tâches
- [ ] Parser les adresses IPv6 en entrée
- [ ] Support CIDR IPv6 (ex: 2001:db8::/32)
- [ ] Adapter Boost.Asio pour dual-stack
- [ ] Tests avec ::1 (loopback)

## Estimation : 1 manday" \
"feature,priority:low" "1" "S1"

# ── MODULE ANALYSE DE CODE (S2) ──────────────
add_task \
"Identification de fonctions C/C++ dangereuses" \
"## Objectif
Détecter l'utilisation de fonctions C/C++ considérées comme dangereuses.

## Fonctions ciblées
| Fonction | Risque | Alternative sécurisée |
|----------|--------|-----------------------|
| gets() | Buffer overflow | fgets() |
| strcpy() | Buffer overflow | strncpy() / std::string |
| sprintf() | Buffer overflow | snprintf() |
| scanf() | Buffer overflow | fgets() + sscanf() |
| strcat() | Buffer overflow | strncat() |
| system() | Command injection | execve() |
| rand() | Crypto faible | /dev/urandom |

## Tâches
- [ ] Parser les fichiers .c et .cpp
- [ ] Signaler ligne + contexte de chaque occurrence
- [ ] Suggérer l'alternative sécurisée

## Estimation : 2 mandays" \
"security,priority:high" "2" "S2"

add_task \
"Détection de buffer overflow et use-after-free" \
"## Objectif
Analyser statiquement le code pour détecter les patterns dangereux.

## Patterns à détecter
- [ ] Accès tableau sans vérification de bounds
- [ ] malloc/free + utilisation post-free
- [ ] Dépassement de buffer dans les boucles
- [ ] Variables non initialisées utilisées
- [ ] Double free

## Approche
Analyse AST simplifiée + patterns regex sur code source C/C++.

## Estimation : 3 mandays" \
"security,priority:high" "3" "S2"

add_task \
"Détection d'injections SQL dans le code source" \
"## Objectif
Identifier les patterns d'injection SQL (concaténation requêtes + input utilisateur).

## Patterns dangereux
\`\`\`cpp
// ❌ Vulnérable
std::string q = \"SELECT * FROM users WHERE id = \" + user_input;

// ✅ Sécurisé (requête préparée)
stmt->setString(1, user_input);
\`\`\`

## Tâches
- [ ] Regex sur concaténations SQL + variables
- [ ] Détecter l'absence de requêtes préparées
- [ ] Détecter command injection (popen + input)
- [ ] Détecter path traversal (fopen + input non sanitisé)

## Estimation : 2 mandays" \
"security,priority:high" "2" "S2"

add_task \
"Audit cryptographique — algorithmes faibles et clés hardcodées" \
"## Objectif
Détecter les algorithmes cryptographiques faibles et secrets hardcodés.

## Vérifications
- [ ] Algorithmes faibles : MD5, SHA1, DES, RC4
- [ ] Clés/mots de passe hardcodés
- [ ] Seeds aléatoires prévisibles (srand(time(0)))
- [ ] Certificats ou tokens dans le code

## Pattern regex clés hardcodées
\`\`\`
(password|secret|key|token|api_key)\s*=\s*[\"'][^\"']{4,}[\"']
\`\`\`

## Estimation : 2 mandays" \
"security,priority:high" "2" "S2"

# ── REPORTING ────────────────────────────────
add_task \
"Export rapport JSON" \
"## Objectif
Générer un rapport au format JSON structuré.

## Structure
\`\`\`json
{
  \"scan_date\": \"2026-02-05T10:30:00Z\",
  \"target\": \"192.168.1.100\",
  \"summary\": { \"critical\": 2, \"high\": 5, \"medium\": 3, \"low\": 1 },
  \"findings\": [
    { \"id\": \"CVE-2024-1234\", \"severity\": \"critical\",
      \"cvss\": 9.8, \"title\": \"...\", \"remediation\": \"...\" }
  ]
}
\`\`\`

## Estimation : 1 manday" \
"feature,priority:high" "1" "S1"

add_task \
"Export rapport HTML" \
"## Objectif
Générer un rapport HTML lisible avec code couleur par sévérité.

## Contenu
- [ ] En-tête avec logo EpiScan + métadonnées du scan
- [ ] Tableau de bord : compteurs Critical/High/Medium/Low
- [ ] Liste des findings avec code couleur CVSS
- [ ] Section recommandations
- [ ] CSS inline (fichier autonome)

## Estimation : 1 manday" \
"feature,priority:medium" "1" "S2"

add_task \
"Export rapport Markdown" \
"## Objectif
Générer un rapport Markdown compatible GitHub.

## Tâches
- [ ] Titres H1/H2/H3 structurés
- [ ] Tableau récapitulatif des findings
- [ ] Badges sévérité : 🔴 Critical 🟠 High 🟡 Medium 🟢 Low
- [ ] Sections par catégorie (réseau, code, SSL)

## Estimation : 1 manday" \
"feature,priority:high" "1" "S2"

add_task \
"Implémentation du scoring CVSS v3.1" \
"## Objectif
Calculer le score CVSS v3.1 pour chaque finding.

## Vecteurs
- AV (Attack Vector) : Network / Adjacent / Local / Physical
- AC (Attack Complexity) : Low / High
- PR (Privileges Required) : None / Low / High
- UI (User Interaction) : None / Required
- S (Scope) : Unchanged / Changed
- CIA Impact : None / Low / High

## Mapping
Chaque type de finding a un vecteur CVSS prédéfini.
Score calculé selon la formule officielle CVSS 3.1.

## Estimation : 2 mandays (S1 + S2)" \
"feature,priority:high" "2" "BOTH"

add_task \
"Recommandations de correction automatiques" \
"## Objectif
Associer une recommandation de correction à chaque type de finding.

## Tâches
- [ ] Base de données de remédiation (JSON)
- [ ] Associer chaque finding à sa recommandation
- [ ] Exemples de code corrigé pour les findings code
- [ ] Liens OWASP / CWE / CVE officiels

## Estimation : 1 manday" \
"feature,priority:medium" "1" "S2"

add_task \
"Statistiques et métriques de sécurité" \
"## Objectif
Calculer et afficher des métriques globales sur le scan.

## Métriques
- [ ] Score de sécurité global (0–100)
- [ ] Répartition findings par catégorie
- [ ] Delta vs scan précédent (si disponible)
- [ ] Temps de scan par module
- [ ] Nombre de ports / fichiers analysés

## Estimation : 1 manday" \
"feature,priority:low" "1" "S1"

# ── TESTS ────────────────────────────────────
add_task \
"Tests unitaires — module réseau" \
"## Objectif
Couvrir le module réseau avec Google Test.

## Tests à implémenter
- [ ] PortScanner : scan localhost:22, 80, 443
- [ ] BannerGrabber : mock TCP server avec banner connu
- [ ] CVEChecker : mock API NVD avec réponse JSON
- [ ] SSLAuditor : certificat de test auto-signé

## Coverage cible : ≥ 70%

## Estimation : 1 manday" \
"testing,priority:medium" "1" "S1"

add_task \
"Tests unitaires — module analyse de code" \
"## Objectif
Couvrir le module d'analyse statique avec Google Test.

## Tests à implémenter
- [ ] DangerousFunctions : gets(), strcpy() → détectés
- [ ] InjectionDetector : snippet SQL vulnérable → détecté
- [ ] CryptoAuditor : MD5 hardcodé → détecté
- [ ] FalsePositiveTest : code sécurisé → 0 finding

## Coverage cible : ≥ 75%

## Estimation : 1 manday" \
"testing,priority:medium" "1" "S2"

add_task \
"Tests d'intégration end-to-end" \
"## Objectif
Valider le pipeline complet : scan → analyse → rapport.

## Scénarios
- [ ] Scan réseau sur serveur de test local (Docker)
- [ ] Analyse du code source d'EpiScan lui-même
- [ ] Génération des 3 formats de rapport (JSON, HTML, MD)
- [ ] Vérification du scoring CVSS sur findings connus

## Estimation : 1 manday (S1 + S2)" \
"testing,priority:low" "1" "BOTH"

# ── DOCS & PERF ──────────────────────────────
add_task \
"Documentation CLI — help et man page" \
"## Objectif
Documenter toutes les options CLI du binaire EpiScan.

## Tâches
- [ ] --help complet avec exemples via CLI11
- [ ] Page man (\`man episcan\`)
- [ ] README Usage section avec cas d'usage courants
- [ ] Exemples pour chaque mode (network, analyze, full)

## Estimation : 1 manday (S1 + S2)" \
"docs,priority:low" "1" "BOTH"

add_task \
"Benchmark performances — comparaison avec Nmap" \
"## Objectif
Mesurer et comparer les performances d'EpiScan vs Nmap.

## Métriques
- [ ] Temps de scan /24 (256 hôtes, ports 1-1024)
- [ ] Consommation CPU et mémoire
- [ ] Taux de faux positifs / négatifs
- [ ] Rapport de benchmark Markdown

## Estimation : 1 manday" \
"perf,priority:medium" "1" "S1"

# ─────────────────────────────────────────────
#  RÉSUMÉ FINAL
# ─────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║   ✅  GitHub Project EpiScan — 100% configuré !             ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  📋 Project  : ${CYAN}https://github.com/${GITHUB_USERNAME}/projects/${PROJECT_NUMBER}${NC}"
echo -e "  🔗 Issues   : ${CYAN}https://github.com/${REPO}/issues${NC}"
echo ""
echo -e "  ${BOLD}Répartition de la charge :${NC}"
echo -e ""
echo -e "  ${BLUE}${STUDENT1}${NC} (S1) — Module réseau + infra build"
echo -e "  $(printf '%-40s' '  Tâches : 10')  16 mandays"
echo -e ""
echo -e "  ${GREEN}${STUDENT2}${NC} (S2) — Analyse de code + reporting"
echo -e "  $(printf '%-40s' '  Tâches : 10')  16 mandays"
echo -e ""
echo -e "  ${CYAN}S1 + S2${NC}  — Architecture, CVSS, e2e, CLI docs"
echo -e "  $(printf '%-40s' '  Tâches : 3 ')   partagées"
echo -e ""
echo -e "  ${BOLD}────────────────────────────────────────────${NC}"
echo -e "  📦 Total : ${BOLD}23 tâches — 32 mandays${NC} (16j / étudiant)"
echo ""