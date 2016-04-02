import ConfigParser
import win32evtlog

# Config file:
cfg_file = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'openerp.cfg', 
    )
    
config = ConfigParser.ConfigParser()
config.read([cfg_file])

# Read parameters:
oerp_server = config.get('openerp', 'server')
port = config.get('openerp', 'port')
dbname = config.get('openerp', 'dbname')
user = config.get('openerp', 'user')
pwd = config.get('openerp', 'pwd')

win_server = config.get('windows', 'server')
logtype = config.get('windows', 'registry')

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
            if event.EventID not in (
                    #4634, # log out
                    4624, # log in
                    #4776, # convalida credenziali
                    #4658, # File system programma
                    #4663, # File system programma
                    #4656, # Cartella
                    ):
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

