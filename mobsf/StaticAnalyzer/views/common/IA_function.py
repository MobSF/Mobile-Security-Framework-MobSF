from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch
import torch.nn.functional as F


def array_to_str(dataset):

    if isinstance(dataset, (list, tuple)):
        cadena = ""
        for x in dataset:
            cadena += x + ","
    else:
        cadena = dataset
    cadena.strip()
    cadena = cadena[:-1]
    if len(cadena) == 0:
        cadena = "Sin_permisos_definidos"

    return cadena


def validate_malware_ia(data):

    permission = list(data.keys()) if data.keys() else []
    permission = array_to_str(permission)
    print("[*]Permisos listado pre IA")
    print(permission)

    model_path = "mobsf\\StaticAnalyzer\\tools\\IA_model\\NyerAndroidMalware"

    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    tokenizer = AutoTokenizer.from_pretrained(model_path)

    # Tokenizar y preparar inputs
    inputs = tokenizer(permission, return_tensors="pt", truncation=True, padding=True)

    # Obtener logits del modelo
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits

    # Obtener probabilidades softmax para cada clase
    probs = F.softmax(logits, dim=1)

    # Suponiendo dos clases: [Benigno, Malware]
    prob_benign, prob_malware = probs[0].tolist()
    # print("[*]Evaluacion HASH: {}".format(data["hash"]))
    print(f"Probabilidad Benigno: {prob_benign * 100:.2f}%")
    print(f"Probabilidad Malware: {prob_malware * 100:.2f}%")

    return {"IA_MALWARE_PERCENTAGE": prob_malware}
