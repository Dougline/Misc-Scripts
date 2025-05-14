import requests
import json
import time
import re
requests.packages.urllib3.disable_warnings()

# === EDITAR ESSAS VARIÁVEIS PARA SEU AMBIENTE ===
misp_url = "https://IP_DO_MISP/attributes/restSearch"
misp_key = "SUA_CHAVE_API_DO_MISP"

qradar_server = "IP_DO_QRADAR"
qradar_token = "SUA_CHAVE_API_DO_QRADAR"

# === HEADERS ===
MISP_headers = {
    "Authorization": misp_key,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

QRadar_headers = {
    "SEC": qradar_token,
    "Content-Type": "application/json"
}

# === CONFIGURAÇÕES POR TIPO ===
configs = [
    {
        "type": "md5",
        "category": "Payload delivery",
        "qradar_ref_set": "MISP_MD5"
    },
    {
        "type": "sha256",
        "category": "Payload delivery",
        "qradar_ref_set": "MISP_SHA256"
    },
    {
        "type": "domain",
        "category": "Network activity",
        "qradar_ref_set": "MISP_Domain"
    },
    {
        "type": "ip-dst",
        "category": "Network activity",
        "qradar_ref_set": "MISP_IPDST"
    },
    {
        "type": "ip-src",
        "category": "Network activity",
        "qradar_ref_set": "MISP_IPSRC"
    },
    {
        "type": "url",
        "category": "Network activity",
        "qradar_ref_set": "MISP_URL"
    },
]

def validate_refSet(ref_set, misp_pdata):
    validate_url = f"https://{qradar_server}/api/reference_data/sets/{ref_set}"
    response = requests.get(validate_url, headers=QRadar_headers, verify=False)
    print(f"{time.strftime('%H:%M:%S')} -- Validando se o reference set {ref_set} existe...")
    if response.status_code == 200:
        ref_type = response.json()["element_type"]
        print(f"{time.strftime('%H:%M:%S')} -- Reference set {ref_set} tipo: {ref_type}")
        get_misp_data(ref_type, ref_set, misp_pdata)
    else:
        print(f"{time.strftime('%H:%M:%S')} -- Reference set {ref_set} NÃO existe no QRadar!")

def get_misp_data(refSet_etype, ref_set, misp_pdata):
    print(f"{time.strftime('%H:%M:%S')} -- Buscando dados do MISP para type={misp_pdata['type']}")
    response = requests.post(misp_url, json=misp_pdata, headers=MISP_headers, verify=False)

    if response.status_code != 200:
        print(f"{time.strftime('%H:%M:%S')} -- ERRO ao consultar o MISP ({response.status_code})")
        return

    json_data = response.json()
    attributes = json_data.get("response", {}).get("Attribute", [])
    ioc_list = [a["value"] for a in attributes if "value" in a]
    print(f"{time.strftime('%H:%M:%S')} -- Recebidos {len(ioc_list)} IOCs do MISP")

    # Validação de IP se necessário
    if refSet_etype == "IP":
        r = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        ioc_list = list(filter(r.match, ioc_list))
        print(f"{time.strftime('%H:%M:%S')} -- Após filtro de IPs válidos: {len(ioc_list)}")

    qradar_post_data(ioc_list, ref_set)

def qradar_post_data(ioc_list, ref_set):
    if not ioc_list:
        print(f"{time.strftime('%H:%M:%S')} -- Nenhum IOC para enviar ao reference set {ref_set}")
        return

    post_url = f"https://{qradar_server}/api/reference_data/sets/bulk_load/{ref_set}"
    response = requests.post(post_url, data=json.dumps(ioc_list), headers=QRadar_headers, verify=False)

    if response.status_code == 200:
        print(f"{time.strftime('%H:%M:%S')} -- Enviados {len(ioc_list)} IOCs para {ref_set}")
    else:
        print(f"{time.strftime('%H:%M:%S')} -- ERRO ao enviar para QRadar ({response.status_code})")

def process_all_types():
    for config in configs:
        pdata = {
            "timestamp": "1d",  # Últimas 24h
            "category": config["category"],
            "type": config["type"]
        }
        validate_refSet(config["qradar_ref_set"], pdata)

if __name__ == "__main__":
    print(f"{time.strftime('%H:%M:%S')} -- Iniciando o script via cron")
    process_all_types()
