from dotenv import load_dotenv
import os

# Charger les variables depuis le fichier .env
load_dotenv()

# Définir les clés API à partir des variables d'environnement
shodan_api_key = os.getenv("SHODAN_API_KEY")
whoisxmlapi_api_key = os.getenv("WHOISXMLAPI_API_KEY")
certspotter_api_key = os.getenv("CERTSPOTTER_API_KEY")
dnsdb_api_key = os.getenv("DNSDB_API_KEY")
virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
recondev_api_key = os.getenv("RECONDEV_API_KEY")
passivetotal_api_key = os.getenv("PASSIVETOTAL_API_KEY")
passivetotal_api_secret = os.getenv("PASSIVETOTAL_API_SECRET")
censys_api_id = os.getenv("CENSYS_API_ID")
censys_api_secret = os.getenv("CENSYS_API_SECRET")
facebook_access_token = os.getenv("FACEBOOK_ACCESS_TOKEN")
binaryedge_api_key = os.getenv("BINARYEDGE_API_KEY")
spyse_api_key = os.getenv("SPYSE_API_KEY")
securitytrails_API = os.getenv("SECURITYTRAILS_API")