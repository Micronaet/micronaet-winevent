import win32evtlog
import xmlrpclib
import ConfigParser

from datetime import datetime

# Config file:
#cfg_file = os.path.join(
#    os.path.dirname(os.path.abspath(__file__)),
#    'openerp.cfg', 
#    )
cfg_file = 'openerp.cfg'
config = ConfigParser.ConfigParser()
config.read([cfg_file])

# Windows parameter:
server = config.get('windows', 'server') # localhost
logtype = config.get('windows', 'registry') #'Security' 

# OpenERP parameter:
rpc_server = config.get('openerp', 'server') # 192.168.1.9
rpc_port = config.get('openerp', 'port')
rpc_username = config.get('openerp', 'user')
rpc_password = config.get('openerp', 'pwd')
rpc_db = config.get('openerp', 'dbname')

# Event ID:
#login_id = int(config.get('ID', 'login'))
#logout_id = int(config.get('ID', 'logout'))
#validate_id = int(config.get('ID', 'validate'))
#fs_program1_id = int(config.get('ID', 'fs_program1'))
#fs_program2_id = int(config.get('ID', 'fs_program2'))
#folder_id = int(config.get('ID', 'folder'))
#check_event_ids = (
#    login_id,
#    # TODO temporary disabled:
#    #logout_id,
#    #validate_id,
#    #fs_program1_id,
#    #fs_program2_id,
#    #folder_id,
#    )


log_file = 'c:\etl\log.security.%s.txt' % datetime.now().strftime(
    '%Y_%m_%d_%H_%S')

# Set up elements:
f_log = open(log_file, 'a')
rpc_sock = xmlrpclib.ServerProxy(
    'http://%s:%s/xmlrpc/common' % (
        rpc_server,
        rpc_port,
        ),
    allow_none=True,
    )
uid = rpc_sock.login(rpc_db, rpc_username, rpc_password)
rpc_sock = xmlrpclib.ServerProxy(
    'http://%s:%s/xmlrpc/object' % (
        rpc_server,
        rpc_port,
        ),
    allow_none=True,
    )

hand = win32evtlog.OpenEventLog(server, logtype)
flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
total = win32evtlog.GetNumberOfEventLogRecords(hand)

# Read event registry:
from_timestamp = '' # TODO
try:
    events = 1
    i = 1
    while events:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        for event in events:
            if i == 1:
                print 'Start: %s' % event.TimeGenerated
            i += 1
            
            # TODO read last timestamp and use it for test for creation
            #if event.TimeGenerated < from_timestamp:
            #    continue # jump old events
            
            if event.EventID not in (
                    #4634, # log out
                    #4624, # log in
                    #4776, # convalida credenziali
                    4663, # File system programma (accesso)
                    #4656, # Apertura oggetto
                    #4658, # Chiusura oggetto
                    ):
                #if i % 100 == 0:
                #    print "Read %s event" % i
                continue
            
            # Read parameters:            
            ts = '%s' % event.TimeGenerated # TS
            timestamp = '20%s-%s-%s %s' % (
                ts[6:8],
                ts[0:2], # american format
                ts[3:5],
                ts[9:],
                )
                
            name = '%s / %s' % (
                event.StringInserts[2], # domain
                event.StringInserts[1], # user
                )
            filename = '%s [%s]' % (
                event.StringInserts[6], # filename
                event.StringInserts[5], # type
                )                
            metadata = '''
                ClosingRecordNumber %s 
                ComputerName %s 
                Data %s 
                EventCategory %s 
                EventID %s 
                EventType %s 
                RecordNumber %s 
                Reserved %s 
                ReservedFlags %s 
                Sid %s 
                SourceName %s 
                StringInserts %s 
                TimeGenerated %s 
                TimeWritten %s \n''' % (
                    event.ClosingRecordNumber,
                    event.ComputerName,
                    event.Data,
                    event.EventCategory,
                    event.EventID,
                    event.EventType,
                    event.RecordNumber,
                    event.Reserved,
                    event.ReservedFlags,
                    event.Sid,
                    event.SourceName,
                    event.StringInserts,
                    event.TimeGenerated,
                    event.TimeWritten,
                    )

            # Write event log:
            # Cases:
            if event.EventID in (4663): # file access event
                rpc_sock.execute(rpc_db, uid, rpc_password, 'audit.fileaccess', 'create', {
                    'name': name,
                    'timestamp': timestamp,
                    # computer
                    'filename': filename,
                    'metadata': metadata,
                    })
                
            elif event.EventID in (4663): # login event #  TODO
                rpc_sock.execute(rpc_db, uid, rpc_password, 'audit.login', 'create', {
                    'name': name,
                    'timestamp': timestamp,
                    # computer
                    #'filename': filename,
                    'metadata': metadata,
                    })
            f_log.write(metadata)            
                           
except:
    print "end"
    try:
        print sys.exc_info()
    except:
        pass

print 'End: %s' % event.TimeGenerated
f_log.close()
