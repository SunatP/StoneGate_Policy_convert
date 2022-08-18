import bs4
import pandas as pd

# Global params
data = []

class FW_Inspection:
    def __init__(self):
        self.data = data
    
    def inspection_entry(self): 
        name = []
        name_rules = []
        is_disabled = []
        disable_fw_rule = []
        sources = []
        destinations = []
        actions = []
        for inspection_template in self.find_all("inspection_template_policy"):
            for inspect in inspection_template.find_all("inspection_entry"):
                for rule_entry in inspect.find_all("rule_entry"):
                    buffer_sources = []
                    buffer_dest = []
                    buffer_actions = []
                    name = "".join(rule_entry['tag'])
                    name_rules.append(name)
                    is_disabled = "".join(rule_entry['is_disabled'])
                    disable_fw_rule.append(is_disabled)
                    for source in rule_entry.find_all("match_sources"):
                        buffer = []
                        for match_source in source.find_all("match_source_ref"):
                            buffer = "".join(match_source["value"])
                            buffer_sources.append(buffer)
                    sources.append(buffer_sources)
                    for destination in rule_entry.find_all("match_destinations"):
                        buffer = []
                        for match_destinations in destination.find_all("match_destination_ref"):
                            buffer = "".join(match_destinations["value"])
                            buffer_dest.append(buffer)
                    destinations.append(buffer_dest)
                    for action in rule_entry.find_all("action"):
                        buffer_actions = "".join(action['type'])
                    actions.append(buffer_actions)

        df0 = pd.DataFrame.from_dict({"Name":name_rules})
        df_disable = pd.DataFrame.from_dict({"Is disable":disable_fw_rule})
        df1 = pd.DataFrame.from_dict({"Sources":sources})
        df1["Sources"] = df1["Sources"].str.join('\n')
        df2 = pd.DataFrame.from_dict({"Destinations":destinations})
        df2["Destinations"] = df2["Destinations"].str.join('\n')
        df3 = pd.DataFrame.from_dict({"Action":actions})
        frames = [df0,df_disable,df1,df2,df3]
        result = pd.concat(frames,axis=1)
        result.to_csv("/output/path/file/here",encoding='utf-8', header=['Name','is_disabled','Sources','Destinations','Action'],index=False)

    def global_inspection_entry(self):
        name = []
        name_rules = []
        is_disabled = []
        disable_fw_rule = []
        sources = []
        destinations = []
        actions = []
        for inspection in self.find_all("inspection_template_policy"):
            for global_inspect in inspection.find_all("global_inspection_entry"):
                for rule_entry in global_inspect.find_all("rule_entry"):
                    buffer_sources = []
                    buffer_dest = []
                    buffer_actions = []
                    name = "".join(rule_entry['tag'])
                    name_rules.append(name)
                    is_disabled = "".join(rule_entry['is_disabled'])
                    disable_fw_rule.append(is_disabled)
                    for source in rule_entry.find_all("match_sources"):
                        buffer = []
                        for match_source in source.find_all("match_source_ref"):
                            buffer = "".join(match_source["value"])
                            buffer_sources.append(buffer)
                    sources.append(buffer_sources)
                    for destination in rule_entry.find_all("match_destinations"):
                        buffer = []
                        for match_destinations in destination.find_all("match_destination_ref"):
                            buffer = "".join(match_destinations["value"])
                            buffer_dest.append(buffer)
                    destinations.append(buffer_dest)
                    for action in rule_entry.find_all("action"):
                        buffer_actions = "".join(action['type'])
                    actions.append(buffer_actions)

        df0 = pd.DataFrame.from_dict({"Name":name_rules})
        df_disable = pd.DataFrame.from_dict({"Is disable":disable_fw_rule})
        df1 = pd.DataFrame.from_dict({"Sources":sources})
        df1["Sources"] = df1["Sources"].str.join('\n')
        df2 = pd.DataFrame.from_dict({"Destinations":destinations})
        df2["Destinations"] = df2["Destinations"].str.join('\n')
        df3 = pd.DataFrame.from_dict({"Action":actions})
        frames = [df0,df_disable,df1,df2,df3]
        result = pd.concat(frames,axis=1)
        result.to_csv("/output/path/file/here",encoding='utf-8', header=['Name','is_disabled','Sources','Destinations','Action'],index=False)

class Firewall_Policy:
    def __init__(self, data):
        self.data = data

    def access_entry(self):
        # for Access Entry
        names = []
        is_fw_disabled = []
        disable_arr = []
        name_rules = []
        sources = []
        destinations = []
        services = []
        actions = []
        for tag in self.find_all("fw_policy",{"name":"firewall_name"}):
            for access in tag.find_all("access_entry"):
                for rule in access.find_all("rule_entry"):
                    buffer_sources = []
                    buffer_dest = []
                    buffer_services = []
                    names =  "".join(rule["tag"])
                    name_rules.append(names)
                    is_fw_disabled = "".join(rule["is_disabled"])
                    disable_arr.append(is_fw_disabled)
                    for src_rule in rule.find_all("match_sources"):
                        buffer = []
                        for each_rule in src_rule.find_all("match_source_ref"):
                            buffer = "".join(each_rule['value'])
                            buffer_sources.append(buffer)
                    sources.append(buffer_sources)
                    for dst_rule in rule.find_all("match_destinations"):
                        buffer = []
                        for each_rule in dst_rule.find_all("match_destination_ref"):
                            buffer = "".join(each_rule['value'])
                            buffer_dest.append(buffer)
                    destinations.append(buffer_dest)
                    for srv_each_rule in rule.find_all("match_services"):
                        buffer = []
                        for srv in srv_each_rule.find_all("match_service_ref"):
                            buffer = "".join(srv['value'])
                            buffer_dest.append(buffer)
                    services.append(buffer_dest)
                    for each_action in rule.find_all("action"):
                        buffer_services = "".join(each_action['type'])
                    actions.append(buffer_services)

        df0 = pd.DataFrame.from_dict({"Name":name_rules})
        df_disable = pd.DataFrame.from_dict({"Is disable":disable_arr})
        df1 = pd.DataFrame.from_dict({"Sources":sources})
        df1["Sources"] = df1["Sources"].str.join('\n')
        df2 = pd.DataFrame.from_dict({"Destinations":destinations})
        df2["Destinations"] = df2["Destinations"].str.join('\n')
        df3 = pd.DataFrame.from_dict({"Services":services})
        df3["Services"] = df3["Services"].str.join('\n')
        df4 = pd.DataFrame.from_dict({"Action":actions})
        frames = [df0,df_disable,df1,df2,df3,df4]
        result = pd.concat(frames,axis=1)
        result.to_csv("/output/path/file/here",encoding='utf-8', header=['Name','is_disabled','Sources','Destinations','Services','Action'],index=False)

    def nat_entry(self):
        # for Nat Entry
        nat_names = []
        nat_is_fw_disabled = []
        nat_disable_arr = []
        nat_name_rules = []
        nat_sources = []
        nat_destinations = []
        nat_services = []
        nat_actions = []
        nat_src_snat = []
        nat_src_snat_new = []
        nat_src_dnat = []
        nat_dst_snat = []
        nat_dst_snat_new = []
        for tag in self.find_all("fw_policy",{"name":"firewall_name"}):
            for nat in tag.find_all("nat_entry"):
                for rule in nat.find_all("rule_entry"):
                    buffer_sources = []
                    buffer_dest = []
                    buffer_services = []
                    nat_names =  "".join(rule["tag"])
                    nat_name_rules.append(nat_names)
                    nat_is_fw_disabled = "".join(rule["is_disabled"])
                    nat_disable_arr.append(nat_is_fw_disabled)
                    for src_rule in rule.find_all("match_sources"):
                        buffer = []
                        for each_rule in src_rule.find_all("match_source_ref"):
                            buffer = "".join(each_rule['value'])
                            buffer_sources.append(buffer)
                    nat_sources.append(buffer_sources)
                    for dst_rule in rule.find_all("match_destinations"):
                        buffer = []
                        for each_rule in dst_rule.find_all("match_destination_ref"):
                            buffer = "".join(each_rule['value'])
                            buffer_dest.append(buffer)
                    nat_destinations.append(buffer_dest)
                    for srv_each_rule in rule.find_all("match_services"):
                        buffer = []
                        for srv in srv_each_rule.find_all("match_service_ref"):
                            buffer = "".join(srv['value'])
                            buffer_dest.append(buffer)
                    nat_services.append(buffer_dest)
                    for each_action in rule.find_all("action"):
                        buffer_services = "".join(each_action['type'])
                    nat_actions.append(buffer_services)
                    for option in rule.find_all("option"):
                        buffer_snat = []
                        buffer_snat_new = []
                        buffer_nat_src_dnat = []
                        buffer_nat_dst_snat = []
                        buffer_nat_dst_snat_new = []
                        if option.nat_src:
                            for nat_src_search in option.find_all("nat_src"):
                                buffer = []
                                buffer_1 = []
                                buffer_2 = [] 
                                for static_nat in nat_src_search.find_all("static_nat"):
                                    buffer = "".join(static_nat.packet_description["ne_ref"])
                                    buffer_1 = "".join(static_nat.packet_description_new["ne_ref"])
                                    buffer_snat.append(buffer) 
                                    buffer_snat_new.append(buffer_1)
                                nat_src_snat.append(buffer_snat)
                                nat_src_snat_new.append(buffer_snat_new)
                                for dynamic_nat in nat_src_search.find_all("dynamic_nat"):
                                    buffer_2 = "".join(dynamic_nat.packet_description["ne_ref"])
                                    buffer_nat_src_dnat.append(buffer_2)
                                nat_src_dnat.append(buffer_nat_src_dnat)
                                buffer_nat_dst_snat.append([])
                                buffer_nat_dst_snat_new.append([])
                            nat_dst_snat.append(buffer_nat_dst_snat)
                            nat_dst_snat_new.append(buffer_nat_dst_snat_new)
                        else:
                            for nat_src_search in option.find_all("nat_dst"):
                                buffer = []
                                buffer_1 = []
                                for static_nat in nat_src_search.find_all("static_nat"):
                                    buffer = "".join(static_nat.packet_description["ne_ref"])
                                    buffer_1 = "".join(static_nat.packet_description_new["ne_ref"])
                                    buffer_nat_dst_snat.append(buffer)
                                    buffer_nat_dst_snat_new.append(buffer_1)
                                nat_dst_snat.append(buffer_nat_dst_snat)
                                nat_dst_snat_new.append(buffer_nat_dst_snat_new)
                                buffer_snat.append([]) 
                                buffer_snat_new.append([])
                                buffer_nat_src_dnat.append([])
                            nat_src_dnat.append(buffer_nat_src_dnat)
                            nat_src_snat.append(buffer_snat)
                            nat_src_snat_new.append(buffer_snat_new)   

        df0 = pd.DataFrame.from_dict({"Name":nat_name_rules})
        df_disable = pd.DataFrame.from_dict({"Is disable":nat_disable_arr})
        df1 = pd.DataFrame.from_dict({"Sources":nat_sources})
        df1["Sources"] = df1["Sources"].str.join('\n')
        df2 = pd.DataFrame.from_dict({"Destinations":nat_destinations})
        df2["Destinations"] = df2["Destinations"].str.join('\n')
        df3 = pd.DataFrame.from_dict({"Services":nat_services})
        df3["Services"] = df3["Services"].str.join('\n')
        df4 = pd.DataFrame.from_dict({"Action":nat_actions})
        df5 = pd.DataFrame.from_dict({"Source SNAT":nat_src_snat})
        df5["Source SNAT"] = df5["Source SNAT"].str.join('\n')
        df_sNAT_new = pd.DataFrame.from_dict({"Source SNAT New":nat_src_snat_new})
        df_sNAT_new["Source SNAT New"] = df_sNAT_new["Source SNAT New"].str.join('\n')
        df6 = pd.DataFrame.from_dict({"Source DNAT":nat_src_dnat})
        df6["Source DNAT"] = df6["Source DNAT"].str.join(", ")
        df7 = pd.DataFrame.from_dict({"Destination SNAT":nat_dst_snat})
        df7["Destination SNAT"] = df7["Destination SNAT"].str.join(", ")
        df8 = pd.DataFrame.from_dict({"Destination NAT New":nat_dst_snat_new})
        df8["Destination NAT New"] = df8["Destination NAT New"].str.join(", ")
        frames = [df0,df_disable,df1,df2,df3,df4,df5,df_sNAT_new,df6,df7,df8]
        result = pd.concat(frames,axis=1)
        result.to_csv("/output/path/file/here",encoding='utf-8', header=['Name','is_disabled','Sources','Destinations','Services','Action','Source SNAT','Source SNAT New','Source DNAT','Destination SNAT','Destination NAT New'],index=False)

        # for NAT Entry
        nat_names = []
        nat_is_fw_disabled = []
        nat_disable_arr = []
        nat_name_rules = []
        nat_sources = []
        nat_destinations = []
        nat_services = []
        nat_actions = []
        nat_src_snat = []
        nat_src_snat_new = []
        nat_src_dnat = []
        nat_dst_snat = []
        nat_dst_snat_new = []
        for tag in self.find_all("fw_policy",{"name":"firewall_name"}):
            for nat in tag.find_all("nat_entry"):
                for rule in nat.find_all("rule_entry"):
                    buffer_sources = []
                    buffer_dest = []
                    buffer_services = []
                    nat_names =  "".join(rule["tag"])
                    nat_name_rules.append(nat_names)
                    nat_is_fw_disabled = "".join(rule["is_disabled"])
                    nat_disable_arr.append(nat_is_fw_disabled)
                    for src_rule in rule.find_all("match_sources"):
                        buffer = []
                        for each_rule in src_rule.find_all("match_source_ref"):
                            buffer = "".join(each_rule['value'])
                            buffer_sources.append(buffer)
                    nat_sources.append(buffer_sources)
                    for dst_rule in rule.find_all("match_destinations"):
                        buffer = []
                        for each_rule in dst_rule.find_all("match_destination_ref"):
                            buffer = "".join(each_rule['value'])
                            buffer_dest.append(buffer)
                    nat_destinations.append(buffer_dest)
                    for srv_each_rule in rule.find_all("match_services"):
                        buffer = []
                        for srv in srv_each_rule.find_all("match_service_ref"):
                            buffer = "".join(srv['value'])
                            buffer_dest.append(buffer)
                    nat_services.append(buffer_dest)
                    for each_action in rule.find_all("action"):
                        buffer_services = "".join(each_action['type'])
                    nat_actions.append(buffer_services)
                    for option in rule.find_all("option"):
                        buffer_snat = []
                        buffer_snat_new = []
                        buffer_nat_src_dnat = []
                        buffer_nat_dst_snat = []
                        buffer_nat_dst_snat_new = []
                        if option.nat_src:
                            for nat_src_search in option.find_all("nat_src"):
                                buffer = []
                                buffer_1 = []
                                buffer_2 = [] 
                                for static_nat in nat_src_search.find_all("static_nat"):
                                    buffer = "".join(static_nat.packet_description["ne_ref"])
                                    buffer_1 = "".join(static_nat.packet_description_new["ne_ref"])
                                    buffer_snat.append(buffer) 
                                    buffer_snat_new.append(buffer_1)
                                nat_src_snat.append(buffer_snat)
                                nat_src_snat_new.append(buffer_snat_new)
                                for dynamic_nat in nat_src_search.find_all("dynamic_nat"):
                                    # Tara have 13 DNAT 
                                    buffer_2 = "".join(dynamic_nat.packet_description["ne_ref"])
                                    buffer_nat_src_dnat.append(buffer_2)
                                nat_src_dnat.append(buffer_nat_src_dnat)
                                buffer_nat_dst_snat.append([])
                                buffer_nat_dst_snat_new.append([])
                            nat_dst_snat.append(buffer_nat_dst_snat)
                            nat_dst_snat_new.append(buffer_nat_dst_snat_new)
                        else:
                            for nat_src_search in option.find_all("nat_dst"):
                                buffer = []
                                buffer_1 = []
                                for static_nat in nat_src_search.find_all("static_nat"):
                                    buffer = "".join(static_nat.packet_description["ne_ref"])
                                    buffer_1 = "".join(static_nat.packet_description_new["ne_ref"])
                                    buffer_nat_dst_snat.append(buffer)
                                    buffer_nat_dst_snat_new.append(buffer_1)
                                nat_dst_snat.append(buffer_nat_dst_snat)
                                nat_dst_snat_new.append(buffer_nat_dst_snat_new)
                                buffer_snat.append([]) 
                                buffer_snat_new.append([])
                                buffer_nat_src_dnat.append([])
                            nat_src_dnat.append(buffer_nat_src_dnat)
                            nat_src_snat.append(buffer_snat)
                            nat_src_snat_new.append(buffer_snat_new)   

        df0 = pd.DataFrame.from_dict({"Name":nat_name_rules})
        df_disable = pd.DataFrame.from_dict({"Is disable":nat_disable_arr})
        df1 = pd.DataFrame.from_dict({"Sources":nat_sources})
        df1["Sources"] = df1["Sources"].str.join('\n')
        df2 = pd.DataFrame.from_dict({"Destinations":nat_destinations})
        df2["Destinations"] = df2["Destinations"].str.join('\n')
        df3 = pd.DataFrame.from_dict({"Services":nat_services})
        df3["Services"] = df3["Services"].str.join('\n')
        df4 = pd.DataFrame.from_dict({"Action":nat_actions})
        df5 = pd.DataFrame.from_dict({"Source SNAT":nat_src_snat})
        df5["Source SNAT"] = df5["Source SNAT"].str.join('\n')
        df_sNAT_new = pd.DataFrame.from_dict({"Source SNAT New":nat_src_snat_new})
        df_sNAT_new["Source SNAT New"] = df_sNAT_new["Source SNAT New"].str.join('\n')
        df6 = pd.DataFrame.from_dict({"Source DNAT":nat_src_dnat})
        df6["Source DNAT"] = df6["Source DNAT"].str.join(", ")
        df7 = pd.DataFrame.from_dict({"Destination SNAT":nat_dst_snat})
        df7["Destination SNAT"] = df7["Destination SNAT"].str.join(", ")
        df8 = pd.DataFrame.from_dict({"Destination NAT New":nat_dst_snat_new})
        df8["Destination NAT New"] = df8["Destination NAT New"].str.join(", ")
        frames = [df0,df_disable,df1,df2,df3,df4,df5,df_sNAT_new,df6,df7,df8]
        result = pd.concat(frames,axis=1)
        result.to_csv("/output/path/file/here",encoding='utf-8', header=['Name','is_disabled','Sources','Destinations','Services','Action','Source SNAT','Source SNAT New','Source DNAT','Destination SNAT','Destination NAT New'],index=False)

class FW_sub_policy:
    def FW_Sub_Policy(data):
        names = []
        fw_disable = []
        disable_arr = []
        name_rules = []
        sources = []
        destinations = []
        services = []
        actions = []
        for x in data.find_all("fw_sub_policy"):
            for y in x.find_all("access_entry"):
                for z in y.find_all("rule_entry"):
                    buffer_sources = []
                    buffer_dest = []
                    buffer_services = []
                    names =  "".join(z["tag"])
                    name_rules.append(names)
                    fw_disable = "".join(z["is_disabled"])
                    disable_arr.append(fw_disable)
                    for a in z.find_all("match_sources"):
                        buffer = []
                        for b in a.find_all("match_source_ref"):
                            buffer = "".join(b['value'])
                            buffer_sources.append(buffer)
                    sources.append(buffer_sources)
                    for a in z.find_all("match_destinations"):
                        buffer = []
                        for b in a.find_all("match_destination_ref"):
                            buffer = "".join(b['value'])
                            buffer_dest.append(buffer)
                    destinations.append(buffer_dest)
                    for a in z.find_all("match_services"):
                        buffer = []
                        for b in a.find_all("match_service_ref"):
                            buffer = "".join(b['value'])
                            buffer_services.append(buffer)
                    services.append(buffer_services)
                    for rule_action in z.find_all("action"):
                        buffer_services = "".join(rule_action['type'])
                    actions.append(buffer_services)
                
        df0 = pd.DataFrame.from_dict({"Name":name_rules})
        df_disable = pd.DataFrame.from_dict({"Is disable":disable_arr})
        df1 = pd.DataFrame.from_dict({"Sources":sources})
        df1["Sources"] = df1["Sources"].str.join('\n')
        df2 = pd.DataFrame.from_dict({"Destinations":destinations})
        df2["Destinations"] = df2["Destinations"].str.join('\n')
        df3 = pd.DataFrame.from_dict({"Services":services})
        df3["Services"] = df3["Services"].str.join('\n')
        df4 = pd.DataFrame.from_dict({"Action":actions})
        frames = [df0,df_disable,df1,df2,df3,df4]
        result = pd.concat(frames,axis=1)
        result.to_csv("/output/path/file/here",encoding='utf-8', header=['Name','is_disabled','Sources','Destinations','Services','Action'],index=False)

if __name__ == '__main__':
    with open("put_xml_file_and_path_here","r",encoding='utf-8',errors='ignore') as file:
        content = file.readlines()
        data = "".join(content)
        bs = bs4.BeautifulSoup(data, "lxml-xml")
    
    # Run code by uncomment this function below
    # FW_Inspection.inspection_entry(bs)
    # FW_Inspection.global_inspection_entry(bs)
    # Firewall_Policy.access_entry(bs)
    # Firewall_Policy.nat_entry(bs)
    # FW_sub_policy.FW_Sub_Policy(bs)