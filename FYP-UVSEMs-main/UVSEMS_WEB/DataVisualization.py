import matplotlib.pyplot as plt
import io
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import base64

class DataViz:
    
    def count_true_values(data):
        counts = {'NMap': 0, 'DNS': 0, 'VAS': 0, 'ZAP': 0}
        
        for scan in data:
            if scan['NMap'] == 'True':
                counts['NMap'] += 1
            if scan['DNS'] == 'True':
                counts['DNS'] += 1
            if scan['VAS'] == 'True':
                counts['VAS'] += 1
            if scan['ZAP'] == 'True':
                counts['ZAP'] += 1
                
        return counts
    
    def bake_a_pie_roles(data):
        role_mapping = {
            '1': 'System Administrator',
            '2': 'Penetration Tester',
            '3': 'Engineer',
            '4': 'Analyst'
        }


        labels = [role_mapping.get(str(role), "Unknown") for role in data.keys()]
        sizes = data.values()

        fig, ax = plt.subplots(figsize=(3, 3))  
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', textprops={'fontsize': 10})  
        ax.axis('equal')  
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')  
        buf.seek(0)
        imagePng = buf.getvalue()
        buf.close()
        image64 = base64.b64encode(imagePng)
        imageStr = image64.decode('utf-8')
        plt.close(fig)  # DOn't forget this Close the plot to free up the memory on every chart
        return imageStr
    
    def bake_a_pie_actions(data):
        labels = data.keys()
        sizes = data.values()
        fig, ax = plt.subplots(figsize=(3, 3))  
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', textprops={'fontsize': 10})  
        ax.axis('equal')  

        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')  
        buf.seek(0)
        imagePng = buf.getvalue()
        buf.close()

        image64 = base64.b64encode(imagePng)
        imageStr = image64.decode('utf-8')
        plt.close(fig)  
        return imageStr

    def bake_CVE_pie(cve_counts):
        high = 0
        medium = 0
        low = 0
        other = 0
        
        for nvt in cve_counts:
                severity = float(nvt['severity'])  
                count = nvt['count']
                if 7.0 <= severity <= 10:
                    high += count
                elif 4.0 <= severity < 7.0:
                    medium += count
                elif 0.1 <= severity < 4.0:
                    low += count
                else:
                    other += count
                
        labels = ['High', 'Medium', 'Low', 'Other']
        sizes = [high, medium, low, other]
        colours = ['red', 'orange', 'blue', 'grey']  


        fig, ax = plt.subplots(figsize=(5, 5))  
        ax.pie(sizes, labels=labels, colors=colours, autopct='%1.1f%%', startangle=90)  
        ax.axis('equal')  

        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')  
        buf.seek(0)
        imagePng = buf.getvalue()
        buf.close()
        image64 = base64.b64encode(imagePng)
        imageStr = image64.decode('utf-8')
        plt.close(fig)  
        return imageStr
    
    def bake_cve_creation_time_chart(cve_creation_data):
        time_periods = [entry['period'] for entry in cve_creation_data]
        cve_counts = [entry['count'] for entry in cve_creation_data]
        fig, ax = plt.subplots(figsize=(10, 8))  
        wedges, _, _ = ax.pie(cve_counts, labels=None, colors=['red', 'orangered', 'blue', 'purple', 'saddlebrown', 'slategrey'],
                            autopct='', startangle=90, wedgeprops=dict(width=0.3))
        for i, entry in enumerate(cve_creation_data):
            ax.text(1.1, 0.95 - 0.05 * i, f"{time_periods[i]}: {entry['count']}",
                    color=wedges[i].get_facecolor(), transform=ax.transAxes,fontsize=24)

        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        buf.seek(0)
        imagePng = buf.getvalue()
        buf.close()
        image64 = base64.b64encode(imagePng)
        imageStr = image64.decode('utf-8')
        plt.close(fig)  
        return imageStr
    
    def bake_cve_creation_by_year(cve_creation_data):

        sorted_data = sorted(cve_creation_data, key=lambda x: x['year'])
        last_5_years_data = sorted_data[-5:]


        years = [entry['year'] for entry in last_5_years_data]
        cve_counts = [entry['total_cves'] for entry in last_5_years_data]
        
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.bar(years, cve_counts, color=['red', 'green', 'blue', 'grey'])  
        ax.set_xlabel('Year')
        ax.set_ylabel('CVE Count')
        ax.set_xticks(years)  
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        buf.seek(0)
        imagePng = buf.getvalue()
        buf.close()
        image64 = base64.b64encode(imagePng)
        imageStr = image64.decode('utf-8')

        plt.close(fig)  

        return imageStr
    
    def bake_scan_bars(data):
        categories = list(data.keys())
        counts = list(data.values())
        
        fig, ax = plt.subplots()
        ax.bar(categories, counts, color=['blue', 'orange', 'green', 'red'])  #  different colours for each bar mix it up
        
        ax.set_ylabel('Counts')
        ax.set_title('Scans Result Availability')
        ax.set_xticks(range(len(categories)))
        ax.set_xticklabels(categories)
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        image_png = buf.getvalue()
        buf.close()

        image64 = base64.b64encode(image_png)
        image_str = image64.decode('utf-8')
        plt.close(fig)  
        return image_str
    
    
    def bake_scan_bars_sev(data):
        full_data = {level: data.get(level, 0) for level in range(1, 11)}
        
        categories = list(full_data.keys())
        counts = list(full_data.values())
        colors = ['green' if x <= 3 else 'orange' if x <= 6 else 'red' for x in categories]
        
        fig, ax = plt.subplots()
        ax.bar(categories, counts, color=colors)
        
        ax.set_ylabel('Counts')
        ax.set_xlabel('Severity Level')
        ax.set_title('Scans Severity Distribution')
        ax.set_xticks(categories)
        ax.set_xticklabels(categories, rotation=45)
        
        plt.tight_layout()
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150)  
        buf.seek(0)
        image_png = buf.getvalue()
        buf.close()

        image64 = base64.b64encode(image_png)
        image_str = image64.decode('utf-8')
        plt.close(fig)  
        return image_str
    
    def bake_pie_risks(data):
        labels_order = ['Informational', 'Low', 'Medium', 'High']
        colors = {'Informational': 'grey', 'Low': 'green', 'Medium': 'orange', 'High': 'red'}
        
        sizes = [data.get(label, 0) for label in labels_order]
        colors_ordered = [colors[label] for label in labels_order if label in data]
        
        fig, ax = plt.subplots()
        ax.pie(sizes, labels=labels_order, autopct='%1.1f%%', startangle=90, colors=colors_ordered)
        ax.axis('equal')  
        plt.title('ZAP Scan Risk Distribution')

        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150)  
        buf.seek(0)
        image_png = buf.getvalue()
        buf.close()

        image64 = base64.b64encode(image_png)
        image_str = image64.decode('utf-8')
        plt.close(fig)  
        return image_str
    
    def bake_scan_owners_pie(data):
        categories = list(data.keys())
        counts = list(data.values())
        fig, ax = plt.subplots()
        ax.pie(counts, labels=categories, autopct='%1.1f%%', startangle=90, colors=['blue', 'orange', 'green', 'red'])
        ax.axis('equal') 
        ax.set_title('Scans by User')
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        image_png = buf.getvalue()
        buf.close()

        image64 = base64.b64encode(image_png)
        image_str = image64.decode('utf-8')
        plt.close(fig)  
        return image_str
    
    def bake_scancounts(nmap_and_dns_count, vas_count, zap_count):
        categories = ['Recon', 'VAS', 'ZAP']
        counts = [nmap_and_dns_count, vas_count, zap_count]
        colors = ['blue', 'purple', 'orange']

        fig, ax = plt.subplots()
        ax.bar(categories, counts, color=colors)

        ax.set_ylabel('Counts')
        ax.set_title('Scan Results Overview')
        ax.set_xticks(range(len(categories)))
        ax.set_xticklabels(categories)

        plt.tight_layout()

        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150)  
        buf.seek(0)
        image_png = buf.getvalue()
        buf.close()
        image64 = base64.b64encode(image_png)
        image_str = image64.decode('utf-8')
        plt.close(fig)  
        return image_str