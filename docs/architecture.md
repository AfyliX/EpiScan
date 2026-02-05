# Architecture de EpiScan

## 📐 Vue d'ensemble

EpiScan suit une architecture modulaire en couches permettant une séparation claire des responsabilités et une extensibilité maximale. Le système est divisé en trois modules principaux (Core, Network, Analyzer) orchestrés par une interface CLI.

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                           │
│                      (User Interface)                       │
│                         main.cpp                            │
└────────────┬─────────────────────────────────┬──────────────┘
             │                                 │
             ↓                                 ↓
┌────────────────────────────┐   ┌────────────────────────────┐
│      Network Module        │   │      Analyzer Module       │
│   (Infrastructure Scan)    │   │   (Code Analysis)          │
├────────────────────────────┤   ├────────────────────────────┤
│ • PortScanner              │   │ • CodeParser               │
│ • ServiceDetector          │   │ • EpiScan (abstract)       │
│ • BannerGrabber            │   │ • UnsafeFunctionDetector   │
│ • NetworkVulnAnalyzer      │   │ • InjectionDetector        │
│                            │   │ • CryptoDetector           │
│ Dependencies:              │   │ • DetectorRegistry         │
│ - Boost.Asio               │   │                            │
│ - OpenSSL                  │   │ Dependencies:              │
│                            │   │ - std::regex               │
└────────────┬───────────────┘   └────────────┬───────────────┘
             │                                │
             └────────────┬───────────────────┘
                          ↓
             ┌────────────────────────────┐
             │       Core Module          │
             │    (Shared Types)          │
             ├────────────────────────────┤
             │ • Vulnerability            │
             │ • Report                   │
             │ • Config                   │
             │ • Severity                 │
             │                            │
             │ Dependencies:              │
             │ - nlohmann/json            │
             │ - spdlog                   │
             └────────────────────────────┘
```

---

## 🏛️ Description des modules

### **Core Module** (Fondation)

**Responsabilité :** Fournir les types de données et la logique commune à tous les modules.

**Composants :**

#### `Severity`
Énumération représentant le niveau de criticité d'une vulnérabilité selon CVSS.

```cpp
enum class Severity {
    Critical,  // Score 9.0-10.0 : Exploitation immédiate, impact maximal
    High,      // Score 7.0-8.9  : Exploitation probable, impact sévère
    Medium,    // Score 4.0-6.9  : Exploitation modérée, impact moyen
    Low,       // Score 0.1-3.9  : Exploitation difficile, impact limité
    Info       // Score 0.0      : Information, pas de risque direct
};
```

#### `Vulnerability`
Classe centrale représentant une vulnérabilité détectée.

**Attributs :**
- `id` : Identifiant unique (ex: "VULN-001", "CVE-2021-44228")
- `title` : Titre court et descriptif
- `description` : Explication détaillée du problème
- `severity` : Niveau de criticité
- `location` : Emplacement (réseau ou code)
- `recommendation` : Conseils de correction
- `cves` : Liste de CVE associés
- `references` : Liens vers documentation externe
- `discoveredAt` : Timestamp de découverte

**Méthodes clés :**
- `toJson()` : Sérialisation JSON
- `fromJson()` : Désérialisation JSON
- `toString()` : Affichage formaté

#### `Report`
Agrégateur de vulnérabilités avec génération de rapports.

**Responsabilités :**
- Collecter toutes les vulnérabilités trouvées
- Calculer des statistiques (total, distribution par sévérité)
- Générer des rapports en multiple formats

**Méthodes principales :**
- `addVulnerability()` : Ajouter une vulnérabilité
- `getCountBySeverity()` : Statistiques par sévérité
- `toJson()` / `toHtml()` / `toMarkdown()` : Export multi-format
- `saveToFile()` : Sauvegarde sur disque

#### `Config`
Gestion de la configuration globale de l'application.

**Sections :**
- `NetworkConfig` : Cibles, ports, timeouts, concurrence
- `AnalyzerConfig` : Chemins, extensions, exclusions, détecteurs actifs
- `ReportConfig` : Format, chemin de sortie, sévérité minimale

**Sources de config :**
1. Fichier JSON (`config.json`)
2. Arguments CLI (priorité sur le fichier)
3. Valeurs par défaut

---

### **Network Module** (Scan d'infrastructure)

**Responsabilité :** Scanner les infrastructures réseau et identifier les vulnérabilités au niveau réseau et services.

**Flux d'exécution :**
```
Input (IP/hostname) 
    ↓
PortScanner → Ports ouverts
    ↓
ServiceDetector → Identification services + versions
    ↓
BannerGrabber → Récupération banners
    ↓
NetworkVulnAnalyzer → Comparaison CVE + vérifications SSL
    ↓
Output (Vulnerability[])
```

#### `PortScanner`
Scanner de ports TCP haute performance avec programmation asynchrone.

**Architecture interne :**
```cpp
class PortScanner {
    boost::asio::io_context ioContext_;        // Event loop
    std::vector<std::thread> threadPool_;      // Pool de threads
    std::counting_semaphore semaphore_;        // Limiteur de concurrence
    ProgressCallback progressCallback_;        // Feedback utilisateur
};
```

**Algorithme de scan :**
1. Créer N connexions TCP asynchrones en parallèle (N = maxConcurrent)
2. Pour chaque port :
   - Lancer `async_connect()` avec timeout
   - Si connexion réussie → port ouvert
   - Si timeout/refus → port fermé/filtré
3. Collecter les résultats au fur et à mesure

**Optimisations :**
- **Semaphore** : Limite le nombre de connexions simultanées pour éviter de saturer le réseau
- **Thread pool** : Réutilise les threads au lieu de les créer/détruire
- **Timeouts courts** : 2 secondes par défaut (ajustable)

**Exemple d'utilisation :**
```cpp
PortScanner scanner(100);  // Max 100 connexions parallèles
auto results = scanner.scanRange("192.168.1.1", 1, 1024);
for (const auto& result : results) {
    if (result.isOpen) {
        std::cout << "Port " << result.port << " open\n";
    }
}
```

#### `ServiceDetector`
Identifie les services qui tournent sur les ports ouverts.

**Méthodes d'identification :**
1. **Port-based** : Ports connus (22=SSH, 80=HTTP, 443=HTTPS, etc.)
2. **Banner grabbing** : Connexion + lecture de la bannière d'accueil
3. **Pattern matching** : Regex pour extraire nom et version du service

**Base de signatures :**
```cpp
struct ServiceSignature {
    std::regex pattern;                              // Ex: "OpenSSH_([\d.]+)"
    std::string serviceName;                         // "SSH"
    std::function<std::string(...)> versionExtractor; // Extraire "8.2p1"
};
```

**Exemple de bannière SSH :**
```
Input:  "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
Output: ServiceInfo {
    name: "SSH",
    version: "8.2p1",
    banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
}
```

#### `BannerGrabber`
Module spécialisé pour récupérer les bannières de services.

**Protocole générique :**
1. Connexion TCP au port
2. Attendre 500ms (certains services envoient directement)
3. Si rien, envoyer une sonde (ex: "GET / HTTP/1.0\r\n\r\n" pour HTTP)
4. Lire la réponse (max 4KB)
5. Timeout après 5 secondes

**Sondes par protocole :**
- **HTTP** : `GET / HTTP/1.0\r\n\r\n`
- **SMTP** : `EHLO test\r\n`
- **FTP** : (attend la bannière automatique)
- **SSH** : (attend la bannière automatique)

#### `NetworkVulnAnalyzer`
Analyse les services détectés pour identifier les vulnérabilités.

**Vérifications effectuées :**

1. **Matching CVE** (base de données)
   ```
   ServiceInfo (Apache 2.4.41) → CPE (cpe:2.3:a:apache:http_server:2.4.41)
   → Recherche dans CVE database → CVE-2021-41773 (Critical)
   ```

2. **Protocoles non sécurisés**
   - Telnet (port 23) : transmission en clair
   - FTP (port 21) : credentials en clair
   - HTTP (port 80) : pas de chiffrement

3. **Versions obsolètes**
   - Services sans mises à jour de sécurité
   - End-of-life software (ex: OpenSSL 1.0.x)

4. **SSL/TLS** (avec OpenSSL)
   - Certificats expirés ou invalides
   - Protocoles faibles (SSLv3, TLS 1.0, TLS 1.1)
   - Cipher suites faibles (DES, RC4, MD5)
   - Absence de Perfect Forward Secrecy

**Format base CVE :**
```json
{
  "id": "CVE-2021-44228",
  "description": "Log4Shell RCE vulnerability",
  "severity": "Critical",
  "cvss_score": 10.0,
  "affected_versions": ["2.0-beta9 to 2.15.0"],
  "cpe": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
}
```

---

### **Analyzer Module** (Analyse de code)

**Responsabilité :** Analyser statiquement le code source pour détecter des patterns de programmation vulnérables.

**Flux d'exécution :**
```
Input (chemin de répertoire)
    ↓
CodeParser → Découverte récursive des fichiers source
    ↓
Pour chaque fichier:
    ParsedFile (contenu + métadonnées)
        ↓
    DetectorRegistry → Exécute tous les détecteurs actifs
        ↓
    [UnsafeFunctionDetector, InjectionDetector, CryptoDetector, ...]
        ↓
    Vulnerability[] (agrégées)
    ↓
Output (Vulnerability[])
```

#### `CodeParser`
Découvre et parse les fichiers source.

**Fonctionnalités :**
- Recherche récursive de fichiers (avec exclusions)
- Lecture et tokenisation des fichiers
- Extraction de métadonnées basiques (includes, fonctions)
- Génération de snippets de code avec contexte

**Algorithme de découverte :**
```cpp
for (auto& entry : recursive_directory_iterator(root)) {
    if (entry.is_directory() && shouldExclude(entry.path())) {
        continue;  // Skip build/, node_modules/, .git/
    }
    if (entry.is_file() && hasValidExtension(entry.path())) {
        files.push_back(entry.path());
    }
}
```

**ParsedFile** (structure de sortie) :
```cpp
struct ParsedFile {
    std::filesystem::path path;           // Chemin absolu
    std::string content;                  // Contenu complet
    std::vector<std::string> lines;       // Ligne par ligne
    std::vector<std::string> includes;    // #include "..."
    std::vector<std::string> functionNames; // Liste des fonctions
};
```

#### `EpiScan` (interface abstraite)
Pattern Strategy pour les détecteurs de vulnérabilités.

```cpp
class EpiScan {
public:
    virtual ~EpiScan() = default;
    
    // Méthode principale : analyser un fichier
    virtual std::vector<Vulnerability> detect(const ParsedFile& file) = 0;
    
    // Métadonnées
    virtual std::string getName() const = 0;
    virtual VulnCategory getCategory() const = 0;
    virtual std::string getDescription() const = 0;
};
```

**Avantages du pattern :**
- Ajout de nouveaux détecteurs sans modifier le code existant
- Tests unitaires indépendants par détecteur
- Activation/désactivation sélective dans la config

#### `UnsafeFunctionDetector`
Détecte l'utilisation de fonctions C/C++ dangereuses.

**Base de règles :**
```cpp
{
    name: "gets",
    reason: "No bounds checking, always causes buffer overflow",
    severity: Critical,
    alternative: "Use fgets(buf, size, stdin) instead",
    pattern: regex(R"(\bgets\s*\()")
}
```

**Fonctions surveillées :**
- **Mémoire** : `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`
- **Conversions** : `atoi` (pas de gestion d'erreur)
- **Système** : `system()` (command injection risk)

**Algorithme de détection :**
```
Pour chaque ligne du fichier:
    Pour chaque fonction dangereuse:
        Si regex.match(ligne):
            Extraire le contexte (ligne ± 2)
            Créer Vulnerability avec:
                - Location (fichier, numéro de ligne)
                - Snippet de code
                - Recommendation (alternative sécurisée)
```

**Exemple de détection :**
```cpp
// Code vulnérable (ligne 42)
char buffer[10];
strcpy(buffer, user_input);  // ⚠️ DÉTECTÉ

// Vulnerability générée :
{
    "id": "UNSAFE-FUNC-42",
    "title": "Unsafe function: strcpy",
    "description": "No bounds checking",
    "severity": "High",
    "location": {
        "file": "src/main.cpp",
        "line": 42,
        "snippet": "strcpy(buffer, user_input);"
    },
    "recommendation": "Use strncpy or std::string"
}
```

#### `InjectionDetector`
Détecte les vulnérabilités d'injection.

**Types d'injections détectées :**

1. **SQL Injection**
   ```cpp
   // Pattern dangereux : concaténation de strings dans requête SQL
   std::string query = "SELECT * FROM users WHERE id = " + userId;
   // ⚠️ Si userId = "1 OR 1=1", toute la table est exposée
   ```

   **Regex :** `(SELECT|INSERT|UPDATE|DELETE).*\+.*`

2. **Command Injection**
   ```cpp
   // Pattern dangereux : system() avec input utilisateur
   std::string cmd = "ping " + userHost;
   system(cmd.c_str());
   // ⚠️ Si userHost = "google.com; rm -rf /", commande malveillante
   ```

   **Regex :** `system\s*\(.*\+.*\)`

3. **Path Traversal**
   ```cpp
   // Pattern dangereux : chemins non validés
   std::string path = "/uploads/" + userFilename;
   // ⚠️ Si userFilename = "../../etc/passwd", accès non autorisé
   ```

   **Regex :** `\.\./|\.\.\\`

**Limitations (approche basique) :**
- Ne trace pas le flow des données (taint analysis)
- Peut générer des faux positifs
- Ne détecte pas les injections complexes

**Évolution possible :**
Implémenter une vraie taint analysis :
```
user_input (tainted) → str1 → str2 → query (tainted) → execute()
                                                          ↑
                                                       DANGER
```

#### `CryptoDetector`
Détecte les problèmes cryptographiques.

**Vérifications :**

1. **Algorithmes faibles**
   ```cpp
   MD5 hash;           // ⚠️ Collisions faciles
   DES cipher;         // ⚠️ Clé 56 bits, cassable
   RC4 stream;         // ⚠️ Biaisé, attaque BEAST
   ```

2. **Clés hardcodées**
   ```cpp
   const char* api_key = "sk_live_abc123...";  // ⚠️ Exposé dans le binaire
   std::string password = "admin123";           // ⚠️ Credentials en dur
   ```

   **Patterns :** `(password|api_key|secret|token)\s*=\s*"[^"]+"`

3. **Générateurs aléatoires faibles**
   ```cpp
   srand(time(NULL));   // ⚠️ Prévisible
   int random = rand(); // ⚠️ Distribution faible
   ```

   **Recommandation :** Utiliser `std::random_device` + `std::mt19937`

#### `DetectorRegistry`
Système de registry pour gérer tous les détecteurs.

**Pattern Singleton :**
```cpp
class DetectorRegistry {
public:
    static DetectorRegistry& instance();  // Point d'accès global
    
    void registerDetector(std::unique_ptr<EpiScan> detector);
    std::vector<Vulnerability> runAll(const ParsedFile& file);
    std::vector<Vulnerability> runCategory(const ParsedFile&, VulnCategory);
    
private:
    DetectorRegistry() = default;  // Constructeur privé
    std::vector<std::unique_ptr<EpiScan>> detectors_;
};
```

**Initialisation (au démarrage) :**
```cpp
auto& registry = DetectorRegistry::instance();
registry.registerDetector(std::make_unique<UnsafeFunctionDetector>());
registry.registerDetector(std::make_unique<InjectionDetector>());
registry.registerDetector(std::make_unique<CryptoDetector>());
```

**Utilisation :**
```cpp
ParsedFile file = parser.parseFile("main.cpp");
auto vulns = registry.runAll(file);  // Exécute tous les détecteurs
```

---

## 🔄 Flux de données complet

### Scénario : Scan complet (network + code)

```
┌─────────────────────────────────────────────────────────────┐
│ 1. INITIALISATION                                           │
│    CLI::parse() → Config → Logger setup                     │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. SCAN RÉSEAU                                              │
│    ┌─────────────────────────────────────────────────┐     │
│    │ Input: 192.168.1.10                             │     │
│    └────────────┬────────────────────────────────────┘     │
│                 ↓                                           │
│    ┌─────────────────────────────────────────────────┐     │
│    │ PortScanner.scanRange(1-1024)                   │     │
│    │ → [22, 80, 443, 3306] (ports ouverts)          │     │
│    └────────────┬────────────────────────────────────┘     │
│                 ↓                                           │
│    Pour chaque port ouvert:                                │
│    ┌─────────────────────────────────────────────────┐     │
│    │ ServiceDetector.detect(192.168.1.10, 22)       │     │
│    │ → ServiceInfo {                                 │     │
│    │     name: "SSH",                                │     │
│    │     version: "OpenSSH_7.4"                      │     │
│    │   }                                             │     │
│    └────────────┬────────────────────────────────────┘     │
│                 ↓                                           │
│    ┌─────────────────────────────────────────────────┐     │
│    │ NetworkVulnAnalyzer.analyze(...)                │     │
│    │ → [CVE-2018-15473] (User enumeration)          │     │
│    └────────────┬────────────────────────────────────┘     │
│                 ↓                                           │
│    Report.addVulnerabilities([...])                        │
└────────────────────┬───────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. ANALYSE CODE                                             │
│    ┌─────────────────────────────────────────────────┐     │
│    │ Input: ./src                                    │     │
│    └────────────┬────────────────────────────────────┘     │
│                 ↓                                           │
│    ┌─────────────────────────────────────────────────┐     │
│    │ CodeParser.findSourceFiles(./src)              │     │
│    │ → [main.cpp, auth.cpp, db.cpp, ...]            │     │
│    └────────────┬────────────────────────────────────┘     │
│                 ↓                                           │
│    Pour chaque fichier:                                    │
│    ┌─────────────────────────────────────────────────┐     │
│    │ CodeParser.parseFile(main.cpp)                  │     │
│    │ → ParsedFile { content, lines, ... }            │     │
│    └────────────┬────────────────────────────────────┘     │
│                 ↓                                           │
│    ┌─────────────────────────────────────────────────┐     │
│    │ DetectorRegistry.runAll(parsedFile)             │     │
│    │   ├─ UnsafeFunctionDetector                     │     │
│    │   │  → [strcpy detected on line 42]             │     │
│    │   ├─ InjectionDetector                          │     │
│    │   │  → [SQL injection on line 108]              │     │
│    │   └─ CryptoDetector                             │     │
│    │      → [MD5 usage on line 215]                  │     │
│    └────────────┬────────────────────────────────────┘     │
│                 ↓                                           │
│    Report.addVulnerabilities([...])                        │
└────────────────────┬───────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. GÉNÉRATION RAPPORT                                       │
│    ┌─────────────────────────────────────────────────┐     │
│    │ Report.getSeverityDistribution()                │     │
│    │ → { Critical: 2, High: 5, Medium: 12, ... }     │     │
│    └────────────┬────────────────────────────────────┘     │
│                 ↓                                           │
│    ┌─────────────────────────────────────────────────┐     │
│    │ Report.saveToFile("report.json")                │     │
│    │ Report.saveToFile("report.html")                │     │
│    └────────────┬────────────────────────────────────┘     │
│                 ↓                                           │
│    Logger: "✅ 19 vulnerabilities found in 2.3s"           │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎨 Design Patterns utilisés

### **1. Strategy Pattern** (EpiScan)
**Problème :** Différents algorithmes de détection de vulnérabilités.
**Solution :** Interface commune `EpiScan`, implémentations multiples.

```cpp
// Interface
class EpiScan {
    virtual std::vector<Vulnerability> detect(...) = 0;
};

// Stratégies concrètes
class UnsafeFunctionDetector : public EpiScan { ... };
class InjectionDetector : public EpiScan { ... };
class CryptoDetector : public EpiScan { ... };

// Utilisation
std::unique_ptr<EpiScan> detector = makeDetector(type);
auto vulns = detector->detect(file);
```

### **2. Registry Pattern** (DetectorRegistry)
**Problème :** Gérer dynamiquement une collection de détecteurs.
**Solution :** Registry centralisé avec enregistrement à l'initialisation.

```cpp
DetectorRegistry& registry = DetectorRegistry::instance();
registry.registerDetector(std::make_unique<UnsafeFunctionDetector>());
// ... plus tard ...
auto vulns = registry.runAll(file);
```

### **3. Builder Pattern** (Vulnerability construction)
**Problème :** Construction complexe d'objets avec beaucoup de paramètres.
**Solution :** Construction progressive avec méthodes chainables.

```cpp
Vulnerability vuln;
vuln.setTitle("Buffer overflow")
    .setDescription("strcpy without bounds check")
    .setSeverity(Severity::High)
    .setRecommendation("Use strncpy")
    .addCVE("CVE-2021-12345");
```

### **4. Factory Pattern** (Vulnerability creation)
**Problème :** Création de différents types de Vulnerability (réseau vs code).
**Solution :** Méthodes factory pour abstraire la création.

```cpp
// Dans EpiScan
Vulnerability createVulnerability(
    const std::string& id,
    const std::string& title,
    // ...
    const ParsedFile& file,
    size_t line
) {
    Vulnerability vuln;
    vuln.setLocation(CodeLocation{file.path, line, 0, snippet});
    // ...
    return vuln;
}
```

### **5. Singleton Pattern** (DetectorRegistry, Config)
**Problème :** Un seul registry/config pour toute l'application.
**Solution :** Constructeur privé + méthode instance() statique.

```cpp
class DetectorRegistry {
public:
    static DetectorRegistry& instance() {
        static DetectorRegistry registry;
        return registry;
    }
private:
    DetectorRegistry() = default;
};
```

### **6. Observer Pattern** (Progress callbacks)
**Problème :** Notifier l'utilisateur de la progression sans couplage fort.
**Solution :** Callbacks enregistrables.

```cpp
scanner.setProgressCallback([](size_t current, size_t total) {
    std::cout << current << "/" << total << " ports scanned\r";
});
```

---

## 🔒 Considérations de sécurité

### **Dans le Network Module**

1. **Rate limiting**
   - Limiter le nombre de scans par seconde pour éviter d'être détecté/bloqué
   - Respecter les infrastructures cibles (pas de DoS)

2. **Timeouts stricts**
   - Éviter les connexions qui pendent indéfiniment
   - Libérer les ressources rapidement

3. **Validation des inputs**
   - Vérifier que les IPs/hostnames sont valides
   - Éviter les injections dans les requêtes réseau

### **Dans l'Analyzer Module**

1. **Sandboxing**
   - Ne jamais exécuter le code analysé
   - Parser uniquement, pas d'eval ou d'interprétation

2. **Limites de ressources**
   - Taille maximale de fichiers (10 MB par défaut)
   - Nombre maximal de fichiers analysés
   - Timeout par fichier

3. **Path traversal protection**
   - Vérifier que les chemins ne sortent pas du répertoire racine
   - Bloquer les symlinks malveillants

---

## 📊 Métriques de performance

### **Objectifs**

- **Scan réseau** : 1000 ports en < 30 secondes
- **Analyse code** : 10 000 lignes en < 5 secondes
- **Mémoire** : < 500 MB pour un projet de 100k lignes
- **Concurrence** : Utilisation de tous les cores CPU disponibles

### **Optimisations clés**

1. **Parallélisation** : Boost.Asio + thread pool
2. **Caching** : Résultats de parsing réutilisables
3. **Lazy loading** : Ne charger que les fichiers nécessaires
4. **Early exit** : Arrêter l'analyse dès qu'une limite est atteinte

---

## 🚀 Extensibilité

### **Ajouter un nouveau détecteur**

```cpp
// 1. Créer la classe
class MyNewDetector : public EpiScan {
public:
    std::vector<Vulnerability> detect(const ParsedFile& file) override {
        // Implémentation
    }
    
    std::string getName() const override { return "MyNewDetector"; }
    VulnCategory getCategory() const override { return VulnCategory::Misc; }
};

// 2. Enregistrer dans le registry
DetectorRegistry::instance().registerDetector(
    std::make_unique<MyNewDetector>()
);

// 3. C'est tout ! Le détecteur sera appelé automatiquement
```

### **Ajouter un nouveau format de rapport**

```cpp
// Dans Report.cpp
std::string Report::toXML() const {
    std::ostringstream xml;
    xml << "<?xml version=\"1.0\"?>\n";
    xml << "<report>\n";
    for (const auto& vuln : vulnerabilities_) {
        xml << "  <vulnerability>\n";
        xml << "    <title>" << vuln.getTitle() << "</title>\n";
        // ...
    }
    return xml.str();
}
```

---

## 📚 Dépendances entre modules

```
┌──────────┐
│   CLI    │ (dépend de tout)
└────┬─────┘
     │
     ├────────────┬────────────┐
     ↓            ↓            ↓
┌─────────┐  ┌─────────┐  ┌──────┐
│ Network │  │Analyzer │  │ Core │
└────┬────┘  └────┬────┘  └──┬───┘
     │            │           │
     └────────────┴───────────┘
              ↓
          (Core uniquement)
```

**Règles de dépendance :**
- `Core` : Ne dépend de rien (fondation)
- `Network` / `Analyzer` : Dépendent uniquement de `Core`
- `CLI` : Dépend de tous les modules
- ⚠️ `Network` et `Analyzer` ne se connaissent pas (découplage)

---

## 🎯 Points d'entrée et orchestration

### **main.cpp** (Orchestrateur principal)

```cpp
int main(int argc, char** argv) {
    // 1. Parse CLI
    Config config = Config::fromCommandLine(argc, argv);
    
    // 2. Init logging
    setupLogger(config.verbose);
    
    // 3. Créer le rapport
    Report report;
    
    // 4. Exécuter les modules demandés
    if (config.shouldScanNetwork()) {
        auto networkVulns = runNetworkScan(config.network());
        report.addVulnerabilities(networkVulns);
    }
    
    if (config.shouldAnalyzeCode()) {
        auto codeVulns = runCodeAnalysis(config.analyzer());
        report.addVulnerabilities(codeVulns);
    }
    
    // 5. Générer et sauvegarder le rapport
    report.saveToFile(config.report().outputPath, config.report().format);
    
    // 6. Afficher le résumé
    printSummary(report);
    
    return 0;
}