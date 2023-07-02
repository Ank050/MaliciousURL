from google.cloud import storage
import joblib
import numpy as np
import pandas as pd
import re
from tld import get_tld, is_tld
from urllib.parse import urlparse

safeurl = None
harmful = None
model = None
safe_typo = None

BUCKET_NAME = "ankmodels"
predd = ["benign", "defacement", "phishing", "malware"]


def download_blob(bucket_name, source_blob_name, destination_file_name):
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(bucket_name)
    blob = bucket.blob(source_blob_name)

    blob.download_to_filename(destination_file_name)

    print(f"Blob {source_blob_name} downloaded to {destination_file_name}.")


def Shortining_Service(url):
    match = re.search(
        "bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
        "yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
        "short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
        "doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"
        "db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|"
        "q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
        "x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
        "tr\.im|link\.zip\.net",
        url,
    )
    if match:
        return 1
    else:
        return 0


def abnormal(url):
    host = urlparse(url).hostname
    host = str(host)
    match = re.search(host, url)
    if match:
        return 1
    else:
        return 0


def safe_url(input_str):
    global safeurl
    if safeurl is None:
        download_blob(
            BUCKET_NAME,
            "models/Web_Scrapped_websites.csv",
            "/tmp/Web_Scrapped_websites.csv",
        )
        safeurl = pd.read_csv("/tmp/Web_Scrapped_websites.csv")
    try:
        result = get_tld(
            input_str, as_object=True, fail_silently=False, fix_protocol=True
        )
        domain = result.parsed_url.netloc
        domain = str(domain)
        domain_str = str(domain)
        print(domain_str)
        if domain_str in safeurl["Website"].values:
            return 1
        else:
            return 0
    except:
        return 0


def harmful_url(input_str):
    global harmful
    if harmful is None:
        download_blob(
            BUCKET_NAME,
            "models/Ultimate.csv",
            "/tmp/Ultimate.csv",
        )
        harmful = pd.read_csv("/tmp/Ultimate.csv")

    try:
        result = get_tld(
            input_str, as_object=True, fail_silently=False, fix_protocol=True
        )
        domain = result.parsed_url.netloc
        domain = str(domain)
        domain = domain.replace("www.", "")
        if domain in harmful["url"].values:
            return 1
        else:
            return 0
    except:
        return 0


def typo_squat(input_str):
    global safe_typo
    if safe_typo is None:
        download_blob(
            BUCKET_NAME,
            "models/Web_Scrapped_websites.csv",
            "/tmp/Web_Scrapped_websites.csv",
        )
        famous_typo = pd.read_csv("/tmp/Web_Scrapped_websites.csv")
    try:
        result = get_tld(
            input_str, as_object=True, fail_silently=False, fix_protocol=True
        )
        domain = result.parsed_url.netloc
        domain = str(domain)
        # print(domain)
        domain = domain.replace("www.", "")
        # print(domain)
        a = domain.split(".")
        # print(a)
        if len(a) > 2:
            web = a[1]
        else:
            web = a[0]
        # print(web)
        # print(web)
        web = re.sub(r"\d", "", web)
        index = famous_typo.loc[famous_typo["Website"].str.contains(web)].index
        # print(index)
        for websites_domain in index:
            if domain[:3] != "www.":
                domain = "www." + domain
            len_web = len(famous_typo["Website"][websites_domain])
            length = len(domain)
            # print(len_web)
            # print(length)
            # print(domain)
            # print(famous_typo["Website"][websites_domain])
            # print(abs(length - len_web))
            diff = abs(length - len_web)
            if diff <= 10 and diff != 0:
                return 1
            else:
                return 0

    except:
        return 0


def data_pre(input_str):
    global model
    if model is None:
        download_blob(
            BUCKET_NAME,
            "models/model_RFC_1.pkl",
            "/tmp/model_RFC_1.pkl",
        )
        loaded_model = joblib.load("/tmp/model_RFC_1.pkl")
    else:
        loaded_model = model
    input_data = {
        "@": [0],
        "?": [0],
        "-": [0],
        "=": [0],
        ".": [0],
        "#": [0],
        "%": [0],
        "+": [0],
        "$": [0],
        "!": [0],
        "*": [0],
        ",": [0],
        "//": [0],
        "abnormal_url": [0],
        "https": [0],
        "digits": [0],
        "letters": [0],
        "Shortining_Service": [0],
    }
    preproc = pd.DataFrame(input_data)
    # print(input_str)
    preproc["@"] = input_str.count("@")
    preproc["?"] = input_str.count("?")
    preproc["-"] = input_str.count("-")
    preproc["="] = input_str.count("=")
    preproc["."] = input_str.count(".")
    preproc["#"] = input_str.count("#")
    preproc["%"] = input_str.count("%")
    preproc["+"] = input_str.count("+")
    preproc["$"] = input_str.count("$")
    preproc["!"] = input_str.count("!")
    preproc["*"] = input_str.count("*")
    preproc[","] = input_str.count(",")
    preproc["//"] = input_str.count("//")
    preproc["abnormal_url"] = abnormal(input_str)
    preproc["https"] = int("https" in input_str)
    preproc["digits"] = sum(1 for char in input_str if char.isdigit())
    preproc["letters"] = sum(1 for char in input_str if char.isalpha())
    preproc["Shortining_Service"] = Shortining_Service(input_str)
    # print(preproc)
    predictions = loaded_model.predict(preproc)
    predd = ["benign", "defacement", "phishing", "malware"]
    return predd[predictions[0]]


def predict(request):
    text = request.form.get("message")
    input_str = re.findall(
        "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\)]|(?:%[0-9a-fA-F][0-9a-fA-F]))+|www\.\S+|\S+\.\S+",
        text,
    )
    if len(input_str) == 0:
        return {"prediction": "no link"}
    input_str = str(input_str[0])
    # print(input_str)
    link_extracted = re.sub(r"[.,'#]+$", "", input_str)
    if safe_url(link_extracted) == 1:
        return {"prediction": "Safe"}
    else:
        if harmful_url(link_extracted) == 1:
            return {"prediction": "Harmful Website"}
        else:
            if typo_squat(link_extracted) == 1:
                return {"prediction": "Typosquatting"}
            else:
                return {"prediction": data_pre(link_extracted)}
