import psycopg2
import os
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential


keyVaultName = os.environ["KEY_VAULT_NAME"]
KVUri = f"https://{keyVaultName}.vault.azure.net"


credential = DefaultAzureCredential()

client = SecretClient(vault_url=KVUri, credential=credential)


def list_access_function(user2query):



    project_list = []

    conn_string = "host="+ client.get_secret('hostdb').value +" port="+ client.get_secret('port').value +" dbname="+ client.get_secret('database').value +" user=" + client.get_secret('userdb').value +" password="+ client.get_secret('passworddb').value
    con = psycopg2.connect(conn_string)
    username = user2query       
    print("Database connection established.", "\n")

    cur = con.cursor()

    cur.execute("SELECT groups, project from userprofilest WHERE username = '" + username + "'")    

    rows = cur.fetchall()

    for row in rows:       

        elemnt = {"project": row[1] }
        permis = []

        for group in row[0]:
            
            cur.execute("SELECT roles from groupst WHERE name = '"+group+"' ")
            row_roles=cur.fetchall()
            
            for row_role in row_roles[0]:
                listprem = str(row_role).replace("[","(").replace("]",")")

                cur.execute("""SELECT                                 
                                json_build_object(
                                            'Access_Level', r.name,
                                            'Description', r.description
                                
                                ) from rolest r
                                where r.name in """+listprem)
            
                roles=cur.fetchall()

                
                for role in roles:
                    if role[0] not in permis:
                        permis.append(role[0])
           
        
        elemnt["Permissions"] = permis
        project_list.append(elemnt)
        
    con.close()
    return project_list
