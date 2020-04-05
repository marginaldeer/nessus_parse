from defusedxml.ElementTree import parse


def scan_root(file):
    """
    Function returns the root element for tree of given nessus file with scan results.
    :param file: given nessus file
    :return: root element for this tree.
    """
    scan_file_parsed = parse(file)
    root = scan_file_parsed.getroot()
    return root

def pref_value(root, pref_name):
    """
    Function returns value for given server preference.
    :param root: root element of scan file tree
    :param preference_name: preference name
    :return:
        preference value - if preference exist
        None - if preference does not exist
    """
    status = 0
    pref_value = None
    for pref in root[0][1][0].findall("preference"):
        pref_name_in_report = pref.findtext('name')
        if pref_name_in_report == pref_name:
            pref_value = pref.findtext('value')
            status = 1
    if status == 0:
        pref_value = None

    return pref_value

def number_of_plugins_per_risk_factor(report_host, risk_factor_level):
    """
    Function returns number of all plugins reported during scan for given risk factor for given target.
    :param report_host: report host element
    :param risk_factor_level:
        'Critical'
        'High'
        'Medium'
        'Low'
        'None'
    :return: number of plugins for given risk factor
    """
    risk_factor_counter = 0
    for report_item in report_host.findall("ReportItem"):
        risk_factor = report_item.find('risk_factor')
        if risk_factor is not None:
            if risk_factor.text == risk_factor_level:
                risk_factor_counter += 1
    return risk_factor_counter

def report_hosts(root):
    """
    Function returns list of report hosts available in given file.
    :param root: root element of scan file tree
    :return: list report hosts
    """
    hosts = root[1].findall("ReportHost")
    return hosts

def report_items(report_host):
    """
    Function returns all items for given target.
    :param report_host: report host element
    :return: list of report items
    """
    items = report_host.findall("ReportItem")
    return items

file = input('Absolute path to nessus file: ')
nessus_file = scan_root(file)
ip_scope = pref_value(nessus_file, 'TARGET').split(',')

crit_total = 0
high_total = 0
med_total = 0
low_total = 0
info_total = 0

for report_host in report_hosts(nessus_file):
    crit = number_of_plugins_per_risk_factor(report_host, 'Critical')
    high = number_of_plugins_per_risk_factor(report_host, 'High')
    med = number_of_plugins_per_risk_factor(report_host, 'Medium')
    low = number_of_plugins_per_risk_factor(report_host, 'Low')
    info = number_of_plugins_per_risk_factor(report_host, 'None')

    crit_total += crit
    high_total += high
    med_total += med
    low_total += low
    info_total += info


    total_vulns = crit_total + high_total + med_total + low_total

    #Build a big Dic

    nessus_data = {}
    nessus_data.update( {'ip_scope' : ip_scope} )
    nessus_data.update( {'auto_total_issues' : total_vulns} )
    nessus_data.update( {'auto_total_crit' : crit_total} )
    nessus_data.update( {'auto_total_high' : high_total} )
    nessus_data.update( {'auto_total_med' : med_total} )
    nessus_data.update( {'auto_total_low' : low_total} )
    nessus_data.update( {'auto_total_info' : info_total} )
print(nessus_data)
