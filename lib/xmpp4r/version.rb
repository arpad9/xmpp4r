# =XMPP4R - XMPP Library for Ruby
# License:: Ruby's license (see the LICENSE file) or GNU GPL, at your option.
# Website::http://home.gna.org/xmpp4r/

require 'xmpp4r/version/helper/responder.rb'
require 'xmpp4r/version/helper/simpleresponder.rb'
require 'xmpp4r/version/iq/version.rb'

module Jabber
  # XMPP4R Version number.  This is the ONLY place where the version number
  # should be specified.  This constant is used to determine the version of
  # package tarballs and generated gems.
  XMPP4R_VERSION = VERSION = '0.8.0'
end
