# Scanner de Sous-domaines avec Tkinter  
Ce projet permet de scanner les sous-domaines d'un domaine en utilisant plusieurs sources d'API externes. 
L'interface graphique est construite avec Tkinter et permet d'afficher, sauvegarder et copier les résultats. 
Il est également possible de coller un domaine directement depuis le presse-papier.  

## Fonctionnalités  
- Scanner des sous-domaines à partir de diverses sources comme `crt.sh`, `SecurityTrails`, `VirusTotal`, `BinaryEdge`, `Shodan` et `Censys`. 
- Télécharger les résultats dans un fichier texte.
- Copier le domaine depuis le presse-papier avec un délai pour mettre à jour le texte.
- Interface graphique avec un clavier virtuel pour faciliter la saisie des domaines.  

## Prérequis  
- Python 3.x - Modules Python nécessaires :
- `tkinter`
- `httpx`
- `pyperclip`
- `config` (voir la section "Configuration des API")  

## Installation  
1. Clonez le repository :

```bash
git clone https://github.com/trh4ckn0n/subdom-gui.git
cd subdom-gui
```
 
1.  
Installez les dépendances :
 `pip install -r requirements.txt ` 
 
2.  
**Configurer les clés API** :

Avant de pouvoir utiliser les sources d'API, vous devez configurer vos clés API dans le fichier `config.py`.

Ce fichier est utilisé pour stocker les clés d'API nécessaires à l'interaction avec les services tiers.
 
### Exemple de configuration dans `config.py` :
 `# Configuration des clés API 
 securitytrails_API = "VOTRE_CLE_SECURITYTRAILS" 
 virustotal_api_key = "VOTRE_CLE_VIRUSTOTAL" 
 binaryedge_api_key = "VOTRE_CLE_BINARYEDGE" 
 shodan_api_key = "VOTRE_CLE_SHODAN" 
 censys_api_id = "VOTRE_CENSYS_API_ID" 
 censys_api_secret = "VOTRE_CENSYS_API_SECRET" ` 
 
Remplacez les valeurs dans le fichier `config.py` par vos clés API personnelles. Voici un résumé des clés API nécessaires :
 
 
  - **SecurityTrails** : [S'inscrire ici](https://securitytrails.com/)
 
  - **VirusTotal** : [S'inscrire ici](https://www.virustotal.com/)
 
  - **BinaryEdge** : [S'inscrire ici](https://www.binaryedge.io/)
 
  - **Shodan** : [S'inscrire ici](https://www.shodan.io/)
 
  - **Censys** : [S'inscrire ici](https://censys.io/)
 

 
 

 
## Utilisation
 
 
1.  
Exécutez le script avec Python :
 `python scanner.py ` 
 
2.  
L'interface graphique s'ouvrira. Entrez un domaine dans le champ de texte, sélectionnez les sources d'API que vous souhaitez utiliser, puis cliquez sur "Scanner".
 
 
3.  
Les résultats des sous-domaines seront affichés dans la zone de texte en bas de l'interface.
 
 
4.  
Vous pouvez sauvegarder les résultats en cliquant sur le bouton "Télécharger".
 
 
5.  
Utilisez le bouton "Coller" pour coller le contenu du presse-papier dans le champ de domaine.
 
 
6.  
Le clavier virtuel peut être activé en cliquant dans le champ de domaine.
 
 

 
## Exemple d'API utilisées
 
### 1. **crt.sh**
 
 
- URL : `https://crt.sh/?q={domain}&output=json`
 
- Pas besoin de clé API.
 

 
### 2. **SecurityTrails**
 
 
- URL : `https://api.securitytrails.com/v1/domain/{domain}/subdomains`
 
- Utilise une clé API dans le fichier `config.py`.
 

 
### 3. **VirusTotal**
 
 
- URL : `https://www.virustotal.com/api/v3/domains/{domain}/subdomains`
 
- Utilise une clé API dans le fichier `config.py`.
 

 
### 4. **BinaryEdge**
 
 
- URL : `https://api.binaryedge.io/v2/query/domains/subdomain/{domain}`
 
- Utilise une clé API dans le fichier `config.py`.
 

 
### 5. **Shodan**
 
 
- URL : `https://api.shodan.io/dns/domain/{domain}?key={api_key}`
 
- Utilise une clé API dans le fichier `config.py`.
 

 
### 6. **Censys**
 
 
- URL : `https://search.censys.io/api/v1/search/certificates`
 
- Utilise des identifiants API dans le fichier `config.py`.
 

 
## Dépannage
 
 
- **Clé API manquante** : Si vous avez oublié de configurer une clé API, l'application vous avertira que vous ne pouvez pas utiliser cette source.
 
- **Erreur de réseau** : Si une erreur de réseau survient, un message d'erreur apparaîtra dans l'interface.
 

 
## License
 
Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.
