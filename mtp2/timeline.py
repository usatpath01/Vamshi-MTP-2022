def parse_users(s):
    user_data = []
    users = s[len('users:(('):-2].replace('(','').replace('"','').split('),')
    for u in users:
        x = dict()
        u_info = u.split(',')
        x['processName'],x['pid'],x['fd'] = u_info[0],u_info[1].split('=')[1],u_info[2].split('=')[1]
        user_data.append(x)
    return user_data

log = open('ss.log', 'r')
lines = log.readlines()

sock_data = []

for line in lines:
    info = line.split()
    # print(info)
    x = dict()
    if info[0] == 'u_str':
        x['type'] = 'UNIX'
    else:
        x['type'] = info[0].upper()
    x['state'] = info[1]

    if x['type'] == 'UNIX':
        x['local_path'],x['local_inode'] = info[4],info[5]
        x['remote_path'],x['remote_inode'] = info[6],info[7]
        x['users'] = parse_users(info[8])
        
    else:
        x['local_ip'],x['local_port']  = info[4].split(':')
        x['remote_ip'],x['remote_port']  = info[5].split(':')
        x['users'] = parse_users(info[6])
    
    sock_data.append(x)

# print(sock_data)

# server - sa_family = inet,addr,port or family=unix,path

def sock_data_client_search(processName, pid, sockfd, server): # connect
    possible_peers = []
    types = []
    if server['sa_family'] == 'AF_INET': # type is tcp/udp
        types.append('TCP'), types.append('UDP')
    elif server['sa_family'] == 'AF_UNIX':
        types.append('UNIX')
    user_info = dict()
    user_info['processName'], user_info['pid'], user_info['fd'] = processName, pid, sockfd
    typesock = []
    for sock in sock_data:
        if sock['type'] not in types or sock['state'] != 'ESTAB' or user_info not in sock['users']:
            continue
        # found a matching socket
        if sock['type'] not in typesock:
            typesock.append(sock['type'])
        if server['sa_family'] == 'AF_UNIX':
            for sock2 in sock_data:
                if sock2['type'] == sock['type'] and sock2['state'] == 'ESTAB' and sock2['local_inode'] == sock['remote_inode']:
                    for peer in sock2['users']:
                        if peer['processName'] not in possible_peers:
                            possible_peers.append(peer['processName'])
        elif server['sa_family'] == 'AF_INET':
            for sock2 in sock_data:
                if sock2['type'] == sock['type'] and sock2['state'] == 'ESTAB' and sock2['local_ip'] == sock['remote_ip'] and sock2['local_port'] == sock['remote_port']:
                    for peer in sock2['users']:
                        if peer['processName'] not in possible_peers:
                            possible_peers.append(peer['processName'])
    return possible_peers,typesock

def sock_data_server_search(processName, pid, sockfd, server): # accept(4)
    return sock_data_client_search(processName, pid, sockfd, server)



import copy
import json
import pandas as pd


file = open('newthing3.json')
data = json.load(file)

process_dict = dict()
rev_process_dict = dict()
cwd_dict = dict()
fd_dict = dict()
socket_dict = dict()
connection_dict = dict()
unresolved_connection = dict()
df = pd.DataFrame(columns=['start',
'Name',
# 'pid','Event',
'content',
# 'Size'
])
print(df)

def resolve_last_hope(peer):
    if peer['sa_family'] == 'AF_UNIX' and peer['sun_path'] == '':
        return "UNKNOWN PROCESS"
    possible_peers = []
    for pid in socket_dict:
        for fd in socket_dict[pid]:
            if 'sa_family' in socket_dict[pid][fd] and peer['sa_family'] == socket_dict[pid][fd]['sa_family']:
                if peer['sa_family'] == 'AF_UNIX':
                    if peer['sun_path'] == socket_dict[pid][fd]['sun_path']:
                        if rev_process_dict[pid] not in possible_peers:
                            possible_peers.append(rev_process_dict[pid])
                if peer['sa_family'] == 'AF_INET':
                    if peer['sin_addr'] == socket_dict[pid][fd]['sin_addr'] and peer['sin_port'] == socket_dict[pid][fd]['sin_port']:
                        if rev_process_dict[pid] not in possible_peers:
                            possible_peers.append(rev_process_dict[pid])
    if len(possible_peers) == 1:
        return '*' + possible_peers[0]
    return "UNKNOWN PROCESS"



for x in data:
    # if 'level' in x and x['level'] == 'warn':
    #     continue
    if x['processName'] not in process_dict:
        process_dict[x['processName']] = set()
    process_dict[x['processName']].add(x['processId'])
    if x['processId'] not in rev_process_dict:
        rev_process_dict[x['processId']] = x['processName']
    if x['processId'] not in cwd_dict:
        cwd_dict[x['processId']] = '/'

    if x['returnValue'] < 0 and x['returnValue'] != -115: # EINPROGRESS
        continue
    if x['eventName'] == 'clone':
        if x['returnValue'] == 0:
            print("Clone called from child process")
        else:
            print("Clone called from parent process", x['processId'], x['returnValue'])
            df = df.append({
                'start':x['timestamp'],
                'Name':x['processName'],
                # 'pid':x['processId'],
                # 'Event':x['eventName'],
                'content':"PID = " + str(x['processId']) +" Cloned child process with pid = " + str(x['returnValue']),
                # 'Size':""
                },
                ignore_index=True)
            if x['processId'] not in fd_dict:
                fd_dict[x['processId']] = dict()
            fd_dict[x['returnValue']] = copy.deepcopy(fd_dict[x['processId']])

            if x['processId'] not in socket_dict:
                socket_dict[x['processId']] = dict()
            socket_dict[x['returnValue']] = copy.deepcopy(socket_dict[x['processId']])

            if x['processId'] not in connection_dict:
                connection_dict[x['processId']] = dict()
            connection_dict[x['returnValue']] = copy.deepcopy(connection_dict[x['processId']])

            if x['processId'] not in cwd_dict:
                cwd_dict[x['processId']] = "/"
            cwd_dict[x['returnValue']] = cwd_dict[x['processId']]

            # unresolved connection
            if x['processId'] in unresolved_connection:
                for fd in unresolved_connection[x['processId']]:
                    possible_peers, typesock = sock_data_server_search(unresolved_connection[x['processId']][fd]['processName'],str(x['returnValue']),str(fd),unresolved_connection[x['processId']][fd]['peer'])
                    # print(possible_peers)
                    sock = "UNKNOWN TYPE"
                    if len(typesock) == 1:
                        sock = typesock[0]
                    peer = "UNKNOWN PROCESS"
                    if len(possible_peers) == 1:
                        peer = possible_peers[0]
                        # del unresolved_connection[x['processId']][fd]
                    connection_dict[x['returnValue']][fd]['peerProcess'] = peer
                    connection_dict[x['returnValue']][fd]['type'] = sock
  
    elif x['eventName'] == 'chdir':
        cwd_dict[x['processId']] = x['args'][0]['value']
        print("CHDIR")
        df = df.append({
                'start':x['timestamp'],
                'Name':x['processName'],
                # 'pid':x['processId'],
                # 'Event':x['eventName'],
                'content':"PID = " + str(x['processId']) +" Changed working directory to " + x['args'][0]['value'],
                # 'Size':""
                },
                ignore_index=True)

    elif x['eventName'] == 'openat':
        if x['processId'] not in fd_dict:
            fd_dict[x['processId']] = dict()

        filepath = x['args'][1]['value']
        if filepath[0] != '/': # relative filepath detected
            if cwd_dict[x['processId']] == '/':
                filepath = '/' + filepath
            else:
                filepath = cwd_dict[x['processId']] + '/' + filepath
        fd_dict[x['processId']][x['returnValue']] = filepath

        print("OPENAT -> ", x['processId'], x['processName'], x['returnValue'], filepath)
    
    elif x['eventName'] == 'write':
        info = {'start':x['timestamp'],
        'Name':x['processName'],
        # 'pid':x['processId'],
        # 'Event':x['eventName'],
        'content':"PID = " + str(x['processId']) +" Write " + str(x['returnValue']) + " bytes to ",
        # 'Size':str(x['returnValue'])
        }
        if x['processId'] in fd_dict:
            if x['args'][0]['value'] in fd_dict[x['processId']]:
                print("WRITE -> ", x['processId'], x['processName'], x['args'][0]['value'], fd_dict[x['processId']][x['args'][0]['value']])
                info['content'] += fd_dict[x['processId']][x['args'][0]['value']]
            else:
                print("WRITE -> ", x['processId'], x['processName'], x['args'][0]['value'], "FILE DESCRIPTOR NOT TRACED")
                info['content'] += "UNKNOWN FILE"
        else:
            print("WRITE -> ", x['processId'], x['processName'], x['args'][0]['value'], "FILE DESCRIPTOR NOT TRACED")
            info['content'] += "UNKNOWN FILE"
        df = df.append(info,ignore_index=True)

    elif x['eventName'] == 'read':
        info = {'start':x['timestamp'],
        'Name':x['processName'],
        # 'pid':x['processId'],
        # 'Event':x['eventName'],
        'content':"PID = " + str(x['processId']) +" Read " + str(x['returnValue']) + " bytes from ",
        # 'Size':str(x['returnValue'])
        }
        if x['processId'] in fd_dict:
            if x['args'][0]['value'] in fd_dict[x['processId']]:
                print("READ -> ", x['processId'], x['processName'], x['args'][0]['value'], fd_dict[x['processId']][x['args'][0]['value']])
                info['content'] += fd_dict[x['processId']][x['args'][0]['value']]
            else: 
                print("READ -> ", x['processId'], x['processName'], x['args'][0]['value'], "FILE DESCRIPTOR NOT TRACED")
                info['content'] += "UNKNOWN FILE"
        else:
            print("READ -> ", x['processId'], x['processName'], x['args'][0]['value'], "FILE DESCRIPTOR NOT TRACED")
            info['content'] += "UNKNOWN FILE"
        df = df.append(info,ignore_index=True)

    elif x['eventName'] == 'rename':
        info = {'start':x['timestamp'],
        'Name':x['processName'],
        # 'pid':x['processId'],
        # 'Event':x['eventName'],
        'content':"Renamed ",
        # 'Size':""
        }
        filepath0 = x['args'][0]['value']
        filepath1 = x['args'][1]['value']
        if filepath0[0] != '/':
            if cwd_dict[x['processId']] == '/':
                filepath0 = '/' + filepath0
            else:
                filepath0 = cwd_dict[x['processId']] + '/' + filepath0
        if filepath1[0] != '/':
            if cwd_dict[x['processId']] == '/':
                filepath1 = '/' + filepath1
            else:
                filepath1 = cwd_dict[x['processId']] + '/' + filepath1
        for fd in fd_dict[x['processId']]:
            if fd_dict[x['processId']][fd] == filepath0:
                fd_dict[x['processId']][fd] = filepath1
        info['content'] +=  filepath0 + " to " + filepath1
        print("PID = " + str(x['processId']) +" RENAME -> ", filepath0, " becomes ", filepath1)
        df = df.append(info,ignore_index=True)

    # elif x['eventName'] == 'close':
    #     if x['processId'] in fd_dict:
    #         if x['args'][0]['value'] in fd_dict[x['processId']]:
    #             print("CLOSE -> ", x['processId'], x['processName'], x['args'][0]['value'], fd_dict[x['processId']][x['args'][0]['value']])
    #             del fd_dict[x['processId']][x['args'][0]['value']]
    #         else:
    #             print("CLOSE ->", x['processId'], x['processName'], x['args'][0]['value'], "FILE DESCRIPTOR NOT TRACED")
    #     else:
    #         print("CLOSE ->", x['processId'], x['processName'], x['args'][0]['value'], "FILE DESCRIPTOR NOT TRACED")

    elif x['eventName'] == 'socket':
        if x['processId'] not in socket_dict:
            socket_dict[x['processId']] = dict()
        socket_dict[x['processId']][x['returnValue']] = dict()
        # print("socket")
    
    elif x['eventName'] == 'bind':
        info = {'start':x['timestamp'],
        'Name':x['processName'],
        # 'pid':x['processId'],
        # 'Event':x['eventName'],
        'content':"PID = " + str(x['processId']) +" Bind ",
        # 'Size':""
        }
        if x['processId'] not in socket_dict:
            socket_dict[x['processId']] = dict()
        if x['args'][0]['value'] not in socket_dict[x['processId']]:
            socket_dict[x['processId']][x['args'][0]['value']] = dict()

        socket_info = copy.deepcopy(x['args'][1]['value'])
        if socket_info['sa_family'] == 'AF_UNIX' and socket_info['sun_path'] != '':
            if socket_info['sun_path'][0] != '/': # relative file path
                if cwd_dict[x['processId']] == '/':
                    socket_info['sun_path'] = '/' + socket_info['sun_path']
                else:
                    socket_info['sun_path'] = cwd_dict[x['processId']] + '/' + socket_info['sun_path']

        socket_dict[x['processId']][x['args'][0]['value']] = socket_info
        info['content'] += str(socket_info) + " to " + str(x['args'][0]['value'])
        df = df.append(info,ignore_index=True)
        # socket_dict[x['processId']][x['args'][0]['value']]['server'] = True # bind syscall used by server

    elif x['eventName'] == 'security_socket_listen':
        info = {'start':x['timestamp'],
        'Name':x['processName'],
        # 'pid':x['processId'],
        # 'Event':'listen',
        'content':"PID = " + str(x['processId']) +" Listen on ",
        # 'Size':""
        }
        if x['processId'] not in socket_dict:
            socket_dict[x['processId']] = dict()
        if x['args'][0]['value'] not in socket_dict[x['processId']]:
            socket_dict[x['processId']][x['args'][0]['value']] = dict()

        socket_info = copy.deepcopy(x['args'][1]['value'])
        if socket_info['sa_family'] == 'AF_UNIX' and socket_info['sun_path'] != '':
            if socket_info['sun_path'][0] != '/': # relative file path
                if cwd_dict[x['processId']] == '/':
                    socket_info['sun_path'] = '/' + socket_info['sun_path']
                else:
                    socket_info['sun_path'] = cwd_dict[x['processId']] + '/' + socket_info['sun_path']

        info['content'] += str(socket_info) + " fd = " + str(x['args'][0]['value'])
        socket_dict[x['processId']][x['args'][0]['value']] = socket_info
        socket_dict[x['processId']][x['args'][0]['value']]['server'] = True # listen syscall used by server
        socket_dict[x['processId']][x['args'][0]['value']]['backlog'] = x['args'][2]['value']
        df = df.append(info,ignore_index=True)
    
    elif x['eventName'] == 'accept' or x['eventName'] == 'accept4':
        # print(x['eventName'], x['processName'], x['processId'],x['returnValue'],x['args'][1]['value'])
        # if x['args'][0]['value'] in socket_dict[x['processId']]:
            # print(socket_dict[x['processId']][x['args'][0]['value']])
        info = {'start':x['timestamp'],
        'Name':x['processName'],
        # 'pid':x['processId'],
        # 'Event':x['eventName'],
        'content':"PID = " + str(x['processId']) +" Accepted connection on socket " + str(socket_dict[x['processId']][x['args'][0]['value']]) + " from ",
        # 'Size':""
        }
        if x['processId'] not in connection_dict:
            connection_dict[x['processId']] = dict()
        possible_peers, typesock = sock_data_server_search(x['processName'],str(x['processId']),str(x['returnValue']),x['args'][1]['value'])
        sock = "UNKNOWN TYPE"
        if len(typesock) == 1:
            sock = typesock[0]
        # print(possible_peers)
        peer = "UNKNOWN PROCESS"
        if len(possible_peers) == 1:
            peer = possible_peers[0]
        else:
            if x['processId'] not in unresolved_connection:
                unresolved_connection[x['processId']] = dict()
            unresolved_connection[x['processId']][x['returnValue']] = {'processName':x['processName'], 'peer':x['args'][1]['value']}
        connection_dict[x['processId']][x['returnValue']] = {'type':sock, 'peerProcess':peer, 'peer':x['args'][1]['value'], 'ourfd':x['args'][0]['value']}
        info['content'] += str(peer) + " " + str(x['args'][1]['value'])
        df = df.append(info,ignore_index=True)

    elif x['eventName'] == 'connect':
        info = {'start':x['timestamp'],
        'Name':x['processName'],
        # 'pid':x['processId'],
        # 'Event':x['eventName'],
        'content':"PID = " + str(x['processId']) +" Connect to ",
        # 'Size':""
        }
        # print(x['eventName'], x['processName'], x['processId'],x['args'][0]['value'])
        if x['processId'] not in connection_dict:
            connection_dict[x['processId']] = dict()
        possible_peers,typesock = sock_data_client_search(x['processName'],str(x['processId']),str(x['args'][0]['value']),x['args'][1]['value'])
        sock = "UNKNOWN TYPE"
        if len(typesock) == 1:
            sock = typesock[0]
        # print(possible_peers)
        peer = "UNKNOWN PROCESS"
        if len(possible_peers) == 1:
            peer = possible_peers[0]
        else:
            peer = resolve_last_hope(x['args'][1]['value'])
        connection_dict[x['processId']][x['args'][0]['value']] = {'type':sock, 'peerProcess':peer, 'peer':x['args'][1]['value'], 'ourfd':x['args'][0]['value']}
        info['content'] += str(peer) + " " + str(x['args'][1]['value']) + " using socket fd " + str(x['args'][0]['value'])
        df = df.append(info,ignore_index=True)

    elif x['eventName'] == 'sendto':
        info = {'start':x['timestamp'],
        'Name':x['processName'],
        # 'pid':x['processId'],
        # 'Event':x['eventName'],
        'content':"PID = " + str(x['processId']) +" Send " + str(x['returnValue']) + " bytes to ",
        # 'Size':str(x['returnValue'])
        }
        if x['processId'] in connection_dict:
            if x['args'][0]['value'] in connection_dict[x['processId']]:
                details = connection_dict[x['processId']][x['args'][0]['value']]
                our_sockdetails = socket_dict[x['processId']][details['ourfd']]
                if details['peerProcess'] == 'UNKNOWN PROCESS':
                    details['peerProcess'] = resolve_last_hope(details['peer'])
                print("SEND TO", x['processName'], "TO", details['peerProcess'], details['peer'], details['type'])
            else:
                print("SEND TO", x['processName'], "TO UNKNOWN PROCESS")
        else:
            print("SEND TO", x['processName'], "TO UNKNOWN PROCESS")
        info['content'] += str(details['peerProcess']) + " " + str(details['peer']) + " " + details['type']
        df = df.append(info,ignore_index=True)
    
    elif x['eventName'] == 'recvfrom':
        info = {'start':x['timestamp'],
        'Name':x['processName'],
        # 'pid':x['processId'],
        # 'Event':x['eventName'],
        'content':"PID = " + str(x['processId']) +" Receive " + str(x['returnValue']) + " bytes from ",
        # 'Size':str(x['returnValue'])
        }  
        if x['processId'] in connection_dict:
            if x['args'][0]['value'] in connection_dict[x['processId']]:
                details = connection_dict[x['processId']][x['args'][0]['value']]
                our_sockdetails = socket_dict[x['processId']][details['ourfd']]
                if details['peerProcess'] == 'UNKNOWN PROCESS':
                    details['peerProcess'] = resolve_last_hope(details['peer'])       
                print("RECV FROM", x['processName'], "FROM", details['peerProcess'], details['peer'], details['type'])
            else:
                print("RECV FROM", x['processName'], "FROM UNKNOWN PROCESS")
        else:
            print("RECV FROM", x['processName'], "FROM UNKNOWN PROCESS")
        info['content'] += str(details['peerProcess']) + " " + str(details['peer']) + " " + details['type']
        df = df.append(info,ignore_index=True)


# print(process_dict)
# print()
# print(socket_dict)
# print()
# print(connection_dict)
# print()
# print(cwd_dict)
# print()
# pd.set_option("display.max_colwidth", None)
# with pd.option_context('display.max_rows', None,
#                        'display.max_columns', None,
#                        'display.precision', 3,
#                        ):
#     print(df)

df.to_pickle("events.pkl")
df.to_csv("events.csv",float_format='{:f}'.format, encoding='utf-8')

df_gunicorn = df.loc[df['Name'] == 'gunicorn', ['start', 'content']]
df_gunicorn.to_pickle("events_g.pkl")
df_gunicorn.to_csv("events_g.csv",float_format='{:f}'.format, encoding='utf-8')


df_nginx = df.loc[df['Name'] == 'nginx', ['start', 'content']]
df_nginx.to_pickle("events_n.pkl")
df_nginx.to_csv("events_n.csv",float_format='{:f}'.format, encoding='utf-8')

df_postgres = df.loc[df['Name'] == 'postgres', ['start', 'content']]
df_postgres.to_pickle("events_p.pkl")
df_postgres.to_csv("events_p.csv",float_format='{:f}'.format, encoding='utf-8')

