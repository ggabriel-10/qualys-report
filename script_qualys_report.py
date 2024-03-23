import xml.etree.ElementTree as ET
import csv
from googletrans import Translator

def translate_text(texts):
    try:
        translator = Translator()
        translated_texts = [translator.translate(text, src='auto', dest='pt').text for text in texts]
    except Exception as e:
        print(f"Erro durante a tradução: {e}")
        translated_texts = texts  # Se ocorrer um erro, mantenha os textos originais
    return translated_texts

def parse_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    print("Script Iniciado")

    vulnerabilities = []

    for ip_element in root.findall('.//IP'):
        ip = ip_element.get('value')

        for vuln_element in ip_element.findall('.//VULN'):
            severity = int(vuln_element.get('severity'))
            threat = vuln_element.find('.//TITLE').text.strip()
            impact = vuln_element.find('.//CONSEQUENCE').text.strip() if vuln_element.find('.//CONSEQUENCE') is not None else ''
            solution = vuln_element.find('.//SOLUTION').text.strip() if vuln_element.find('.//SOLUTION') is not None else ''

            if severity >= 2:
                # Traduzindo os campos IMPACT e Solution
                translated_impact, translated_solution = translate_text([impact, solution])
                vulnerabilities.append({
                    'IP': ip,
                    'Severity': severity,
                    'THREAT': threat,
                    'IMPACT': translated_impact,
                    'Solution': translated_solution
                })

        for cat_element in ip_element.findall('.//CAT'):
            cat_value = cat_element.get('value')

            for info_element in cat_element.findall('.//INFO'):
                severity = int(info_element.get('severity'))

                if severity >= 2:
                    diagnosis_element = info_element.find('.//DIAGNOSIS')
                    diagnosis = translate_text([diagnosis_element.text.strip()]) if diagnosis_element is not None else ''

                    consequence_element = info_element.find('.//CONSEQUENCE')
                    consequence = translate_text([consequence_element.text.strip()]) if consequence_element is not None else ''

                    solution_element = info_element.find('.//SOLUTION')
                    solution = translate_text([solution_element.text.strip()]) if solution_element is not None else ''

                    vulnerabilities.append({
                        'IP': ip,
                        'Category': cat_value,
                        'Severity': severity,
                        'THREAT': diagnosis[0] if diagnosis else '',  # Ajuste para acessar o primeiro item da lista traduzida
                        'IMPACT': consequence[0] if consequence else '',  # Ajuste para acessar o primeiro item da lista traduzida
                        'Solution': solution[0] if solution else ''  # Ajuste para acessar o primeiro item da lista traduzida
                    })

            for service_element in cat_element.findall('.//SERVICE'):
                severity = int(service_element.get('severity'))

                if severity >= 2:
                    diagnosis_element = service_element.find('.//DIAGNOSIS')
                    diagnosis = translate_text([diagnosis_element.text.strip()]) if diagnosis_element is not None else ''

                    consequence_element = service_element.find('.//CONSEQUENCE')
                    consequence = translate_text([consequence_element.text.strip()]) if consequence_element is not None else ''

                    solution_element = service_element.find('.//SOLUTION')
                    solution = translate_text([solution_element.text.strip()]) if solution_element is not None else ''

                    vulnerabilities.append({
                        'IP': ip,
                        'Category': cat_value,
                        'Severity': severity,
                        'THREAT': diagnosis[0] if diagnosis else '',  # Ajuste para acessar o primeiro item da lista traduzida
                        'IMPACT': consequence[0] if consequence else '',  # Ajuste para acessar o primeiro item da lista traduzida
                        'Solution': solution[0] if solution else ''  # Ajuste para acessar o primeiro item da lista traduzida
                    })

    return vulnerabilities

def write_to_csv(vulnerabilities, output_file):
    with open(output_file, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['IP', 'Category', 'Severity', 'THREAT', 'IMPACT', 'Solution'], delimiter=';')
        writer.writeheader()
        writer.writerows(vulnerabilities)

if __name__ == "__main__":
    xml_file = "Hagana_CTH_0-60.xml"
    output_file = "output_vulnerabilities.csv"

    vulnerabilities = parse_xml(xml_file)
    write_to_csv(vulnerabilities, output_file)

print("Script Finalizado")
