# -*- coding: utf-8 -*-
###############################################################################
#
#    Copyright (C) 2001-2014 Micronaet SRL (<http://www.micronaet.it>).
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as published
#    by the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################
import os
import sys
import logging
import openerp
import openerp.netsvc as netsvc
import openerp.addons.decimal_precision as dp
from openerp.osv import fields, osv, expression, orm
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from openerp import SUPERUSER_ID
from openerp import tools
from openerp.tools.translate import _
from openerp.tools.float_utils import float_round as round
from openerp.tools import (DEFAULT_SERVER_DATE_FORMAT, 
    DEFAULT_SERVER_DATETIME_FORMAT, 
    DATETIME_FORMATS_MAP, 
    float_compare)


_logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
#                                Parameters
# -----------------------------------------------------------------------------
class AuditLogon(osv.osv):
    """ Model name: AuditLogon
    """
    _name = 'audit.logon'
    _description = 'Audit logon event'
    _order = 'timestamp'
    
    def get_last_timestamp(self, cr, uid, context=None):
        ''' Return last time stamp date 
            used to append from that value (called from XMLRPC)
        '''
        return False
    
    _columns = {
        'name': fields.char('Login name', size=64, required=True),
        'timestamp': fields.datetime('Timestamp', required=False),    
        'computer': fields.char('PC name', size=64),
        'event_category': fields.char('Category', size=64),
        'event_id': fields.char('Event ID', size=64),
        'event_reserved': fields.char('Event reserved', size=64),
        'event_flags': fields.char('Event flags', size=64),
        # SID
        # Source name
        # String Inserts
        # Time generated
        # Time written
        
        'type': fields.selection([
            ('in', 'Log in'),
            ('out', 'Log out'),
            ], 'Type', readonly=True),        
        'metadata': fields.text('Metadata', help='Original event'),
        }
        
    _defaults = {
        # Default value:
        'type': lambda *x: 'in',
        }    

class AuditFileaccess(osv.osv):
    """ Model name: Audit Access to file
    """
    _name = 'audit.fileaccess'
    _description = 'Audit file access event'
    _order = 'timestamp'
    
    def get_last_timestamp(self, cr, uid, context=None):
        ''' Return last time stamp date 
            used to append from that value (called from XMLRPC)
        '''
        return False
    
    _columns = {
        'name': fields.char('Login name', size=64, required=True),
        'timestamp': fields.date('Timestamp', required=False),    
        'computer': fields.char('PC name', size=64),
        'filename': fields.char('File', size=200),        
        'metadata': fields.text('Metadata', help='Original event'),
        }
        
    _defaults = {
        }    
# vim:expandtab:smartindent:tabstop=4:softtabstop=4:shiftwidth=4:
