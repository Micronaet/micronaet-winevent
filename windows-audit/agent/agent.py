import ConfigParser
import win32evtlog

# Config file:
cfg_file = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'openerp.cfg', 
    )
    
config = ConfigParser.ConfigParser()
config.read([cfg_file])

# -----------------------------------------------------------------------------
# Read parameters:
# -----------------------------------------------------------------------------

# OpenERP parameter:
oerp_server = config.get('openerp', 'server')
port = config.get('openerp', 'port')
dbname = config.get('openerp', 'dbname')
user = config.get('openerp', 'user')
pwd = config.get('openerp', 'pwd')

# Windows reg settings:
win_server = config.get('windows', 'server')
logtype = config.get('windows', 'registry')

# Event ID:
login_id = int(config.get('ID', 'login'))
logout_id = int(config.get('ID', 'logout'))
validate_id = int(config.get('ID', 'validate'))
fs_program1_id = int(config.get('ID', 'fs_program1'))
fs_program2_id = int(config.get('ID', 'fs_program2'))
folder_id = int(config.get('ID', 'folder'))


check_event_ids = (
    login_id,
    #logout_id,
    #validate_id,
    #fs_program1_id,
    #fs_program2_id,
    #folder_id,
    )
# -----------------------------------------------------------------------------
# XMLRPC connection for autentication (UID) and proxy 
# -----------------------------------------------------------------------------
sock = xmlrpclib.ServerProxy(
    'http://%s:%s/xmlrpc/common' % (oerp_server, port), allow_none=True)
uid = sock.login(dbname, user, pwd)
sock = xmlrpclib.ServerProxy(
    'http://%s:%s/xmlrpc/object' % (oerp_server, port), allow_none=True)

# -----------------------------------------------------------------------------
# Windows: read registry:
# -----------------------------------------------------------------------------
hand = win32evtlog.OpenEventLog(win_server, logtype)
flags = \
    win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
total = win32evtlog.GetNumberOfEventLogRecords(hand)

try:
    events = 1
    while events:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        for event in events:
            if event.EventID not in check_event_ids:
                continue
            print '''
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
                TimeWritten %s\n''' % (
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
except:
    print "end"

