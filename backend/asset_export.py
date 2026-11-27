"""Fill the sanitized asset template without runtime Excel/third-party dependencies."""
from copy import deepcopy
from datetime import datetime, timezone
from io import BytesIO
import math
from pathlib import Path
import re
from xml.etree import ElementTree as ET
from zipfile import ZipFile, ZIP_DEFLATED

NS='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
ET.register_namespace('',NS)
TEMPLATE=Path(__file__).parent/'templates'/'asset_inventory.xlsx'


def column(index):
    result=''
    while index:
        index,rem=divmod(index-1,26)
        result=chr(65+rem)+result
    return result


def asset_row(device,index,softwares):
    name=device['name']
    ip=str(device.get('ip_address') or '')
    os_version=device.get('os_version') or ''
    location=device.get('location') or ''
    if device['type']=='server':
        row=['']*28
        row[0],row[6],row[7],row[9],row[10],row[13]=index,name,name,location,ip,os_version
        web,db=[],[]
        for item in softwares:
            label=(item['name']+' '+item['version']).strip()
            if re.search(r'php|node.?js|tomcat|httpd|nginx|apache',item['name'],re.I): web.append(label)
            if re.search(r'postgres|mysql|mariadb|sql server|oracle database|mongodb',item['name'],re.I): db.append(label)
        row[14],row[15]='\n'.join(sorted(set(web))),'\n'.join(sorted(set(db)))
    elif device['type']=='switch':
        row=['']*22
        row[0],row[6],row[7],row[10],row[11],row[12]=index,name,name,location,ip,os_version
    else:
        row=['']*16
        row[0],row[1],row[3],row[4],row[5],row[7]=index,name,device['type'],1,location,ip
    return row


def build_asset_workbook(devices,software):
    grouped=[[d for d in devices if d['type']=='server'],[d for d in devices if d['type']=='switch'],
             [d for d in devices if d['type'] not in ('server','switch')]]
    inventory={}
    for item in software: inventory.setdefault(item['device_id'],[]).append(item)
    result=BytesIO()
    with ZipFile(TEMPLATE) as source,ZipFile(result,'w',ZIP_DEFLATED) as target:
        for entry in source.infolist():
            data=source.read(entry.filename)
            match=re.fullmatch(r'xl/worksheets/sheet([123])\.xml',entry.filename)
            if match:
                group=grouped[int(match[1])-1]
                tree=ET.fromstring(data)
                sheet_data=tree.find('{%s}sheetData'%NS)
                template=sheet_data.find("{%s}row[@r='6']"%NS)
                styles={c.attrib['r'].rstrip('0123456789'):c.get('s','0') for c in template} if template is not None else {}
                for row in list(sheet_data):
                    if int(row.get('r','0'))>=6: sheet_data.remove(row)
                for number,device in enumerate(group,1):
                    values=asset_row(device,number,inventory.get(device['id'],[]))
                    lines=max(sum(max(1,math.ceil(len(line)/16)) for line in str(value).split('\n')) for value in values)
                    row=ET.SubElement(sheet_data,'{%s}row'%NS,{'r':str(number+5),'ht':str(min(400,max(42,lines*15))),'customHeight':'1'})
                    for col,value in enumerate(values,1):
                        letter=column(col)
                        cell=ET.SubElement(row,'{%s}c'%NS,{'r':letter+str(number+5),'s':styles.get(letter,'0'),'t':'inlineStr'})
                        # Inline strings cannot execute spreadsheet formulas.
                        text=ET.SubElement(ET.SubElement(cell,'{%s}is'%NS),'{%s}t'%NS)
                        text.text=re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]','',str(value))[:32767]
                        text.set('{http://www.w3.org/XML/1998/namespace}space','preserve')
                cols=(28,22,16)[int(match[1])-1]
                dim=tree.find('{%s}dimension'%NS)
                if dim is not None: dim.set('ref','A1:'+column(cols)+str(max(5,len(group)+5)))
                for filter_node in tree.findall('{%s}autoFilter'%NS): tree.remove(filter_node)
                filter_node=ET.Element('{%s}autoFilter'%NS,{'ref':'A5:'+column(cols)+str(max(5,len(group)+5))})
                tree.insert(list(tree).index(sheet_data)+1,filter_node)
                data=ET.tostring(tree,encoding='utf-8',xml_declaration=True)
            target.writestr(entry.filename,data)
    return result.getvalue()
