# =XMPP4R - XMPP Library for Ruby
# License:: Ruby's license (see the LICENSE file) or GNU GPL, at your option.
# Website::http://home.gna.org/xmpp4r/

# TODO: eval  <body type='terminate' condition=

require 'xmpp4r/client'
require 'xmpp4r/semaphore'
require 'net/http'

module Jabber
  module HTTPBinding
    ##
    # This class implements an alternative Client
    # using HTTP Binding (JEP0124).
    #
    # This class is designed to be a drop-in replacement
    # for Jabber::Client, except for the
    # Jabber::HTTP::Client#connect method which takes an URI
    # as argument.
    #
    # HTTP requests are buffered to not exceed the negotiated
    # 'polling' and 'requests' parameters.
    #
    # Stanzas in HTTP resonses may be delayed to arrive in the
    # order defined by 'rid' parameters.
    #
    # =Debugging
    # Turning Jabber::debug to true will make debug output
    # not only spit out stanzas but HTTP request/response
    # bodies, too.
    class Client < Jabber::Client

      # Content-Type to be used for communication
      # (you can set this to "text/html")
      attr_accessor :http_content_type
      # The server should wait this value seconds if
      # there is no stanza to be received
      attr_accessor :http_wait
      # The server may hold this amount of stanzas
      # to reduce number of HTTP requests
      attr_accessor :http_hold

      # Need to SID and RID available to be able
      # to create a connection manager and pass
      # the values to a Bosh Javascript page
      attr_accessor :http_rid
      attr_accessor :http_sid
      attr_accessor :connection_only

      # In some cases, we may be trying to call a 
      # close on a non-existent and erroring
      # connection
      attr_accessor :status

      # Other Net::HTTP config options
      attr_accessor :read_timeout
      attr_accessor :use_ssl
      attr_accessor :ssl_verify
      attr_accessor :http_inactivity
      attr_accessor :http_connect

      ##
      # Initialize
      # jid:: [JID or String]
      # proxy:: [Net::HTTP] Proxy class (via Net::HTTP::Proxy).
      def initialize(jid, proxy=nil)
        super(jid)
        @lock = Mutex.new
        @http = proxy || Net::HTTP
        @http_wait = 60
        @http_hold = 2
        @http_connect = 60      # :http_connect => time in seconds to wait for initial connection
        @http_inactivity = 60   # :http_inactivity => value to use for http_inactivity in case the server does not specify.
        @ssl_verify = true      # :ssl_verify => false to defeat peer certificate verify
        @http_content_type = 'text/xml; charset=utf-8'
        @allow_tls = false      # Shall be done at HTTP level
        @connection_only = false # For getting and passing connections to other Bosh clients
        initialize_for_connect  # Actually unnecessary, but nice to have these variables defined here
      end

      ##
      # A function to use if you only want to create
      # a connection for passing off to another Bosh
      # client.  This could also be done by calling
      # connect() and setting @connection_only to
      # true, but this makes it clear and convenient
      #
      # uri:: [URI::Generic or String]
      # host:: [String] Optional host to route to
      # port:: [Fixnum] Port for route feature
      def connect_only( uri, host = nil, port = 5222 )
        @http_wait = 60
        @read_timeout = 300 
        @http_inactivity = 60
        @connection_only = true
        connect( uri, host, port )
      end

      ##
      # Set up the stream using uri as the HTTP Binding URI
      #
      # You may optionally pass host and port parameters
      # to make use of the JEP0124 'route' feature.
      #
      # uri:: [URI::Generic or String]
      # host:: [String] Optional host to route to
      # port:: [Fixnum] Port for route feature
      def connect( uri, host=nil, port=5222 )
        @keepalive_interval = nil if @connection_only

        initialize_for_connect  # Initial/default values for new connection, in case
                                # of connect/close/connect/close/connect on same object...

        uri = URI::parse(uri) unless uri.kind_of? URI::Generic
        @uri = uri
        @use_ssl = @uri.kind_of? URI::HTTPS
        @protocol_name = "HTTP#{'S' if @use_ssl}"
        @verify_mode = @ssl_verify ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE if @use_ssl

        @http_rid = IdGenerator.generate_id.to_i
        @pending_rid = @http_rid
        @pending_rid_lock = Semaphore.new

        req_body = REXML::Element.new('body')
        req_body.attributes['rid'] = @http_rid
        req_body.attributes['content'] = @http_content_type
        req_body.attributes['hold'] = @http_hold.to_s
        req_body.attributes['wait'] = @http_wait.to_s
        req_body.attributes['to'] = @jid.domain
        req_body.attributes['ver'] = '1.8'
        if host
          req_body.attributes['route'] = "xmpp:#{host}:#{port}"
        end
        req_body.attributes['secure'] = 'true'
        req_body.attributes['xmlns'] = 'http://jabber.org/protocol/httpbind'
        req_body.attributes['xmlns:xmpp'] = 'urn:xmpp:xbosh'
        req_body.attributes['xmpp:version'] = '1.0'
        begin
          res_body = post(req_body)
        rescue Net::HTTPBadResponse => e
          raise
        rescue Timeout::Error => e
          raise
        rescue => e
          raise
        end

        unless res_body.name == 'body'
          raise 'Response body is no <body/> element'
        end

        @streamid = res_body.attributes['authid']
        @status = CONNECTED
        @http_sid = res_body.attributes['sid']
        @http_wait = res_body.attributes['wait'].to_i if res_body.attributes['wait']
        @http_hold = res_body.attributes['hold'].to_i if res_body.attributes['hold']
        @http_inactivity = res_body.attributes['inactivity'].to_i if res_body.attributes['inactivity']
        @http_polling = res_body.attributes['polling'].to_i
        @http_polling = 5 if @http_polling == 0
        @http_requests = res_body.attributes['requests'].to_i
        @http_requests = 1 if @http_requests == 0

        receive_elements_with_rid(@http_rid, res_body.children)

        @features_sem.run
      end

      ##
      # Send an empty body with specific attributes
      #
      # attributes:: [Hash] key, value attributes for
      #              insertion into the body
      def send_body( attributes = {} )
        @body_attributes = attributes
        post_data
      end

      ##
      # Ensure that there is one pending request
      #
      # Will be automatically called if you've sent
      # a stanza.
      def ensure_one_pending_request
        return if is_disconnected?
        
        # I don't want a request sent if
        # I'm just using this to start aconneciton, it
        # messes up the rid sequence when passing
        # a connection off
        return if @connection_only

        if @lock.synchronize { @pending_requests } < 1
          send_data('')
        end
      end

      ##
      # Close the session by sending
      # <presence type='unavailable'/>
      def close
        @status = DISCONNECTED
        send(Jabber::Presence.new.set_type(:unavailable))
      end

      ##
      # Send a body element with xmpp:restart set to true.
      def restart
        r = REXML::Element.new 'body'
        r.attributes['rid'] = @http_rid += 1
        r.attributes['sid'] = @http_sid
        r.attributes['to'] = @jid.domain
        r.attributes['xmlns'] = 'http://jabber.org/protocol/httpbind'
        r.attributes['xmlns:xmpp'] = 'urn:xmpp:xbosh'
        r.attributes['xmpp:restart'] = 'true'
        s = post(r)
        unless s.name == 'body'
          raise 'Response body is no <body/> element'
        end
        receive_elements_with_rid(@http_rid, s.children)
      end

      private

      # (re)initialize instances vars prior to connect()
      def initialize_for_connect
        @initial_post = true
        @http_requests = 1
        @pending_requests = 0
        @last_send = Time.at(0)
        @previous_send = Time.at(0)
        @send_buffer = ''
        @stream_mechanisms = []
        @stream_features = {}
        @retry_error = 0
      end

      ##
      # Receive stanzas ensuring that the 'rid' order is kept
      # result:: [REXML::Element]
      def receive_elements_with_rid(rid, elements)
        while rid > @pending_rid
          @pending_rid_lock.wait
        end
        @pending_rid = rid + 1

        elements.each { |e|
          receive(e)
        }

        @pending_rid_lock.run
      end

      ##
      # Do a POST request
      def post(body)
        body = body.to_s
        request = Net::HTTP::Post.new(@uri.path)
        request.content_length = body.size
        request.body = body
        request['Content-Type'] = @http_content_type

        # Server will disconnect @http_inactivity seconds after receiving previous client
        # response, unless it receives the post we are now sending.
        # Net::HTTP defaults to 60 seconds, which would not always be appropriate.
        # In particular, the default would not work if @http_wait is > 60!
        if @read_timeout
          read_timeout = @read_timeout
        elsif @initial_post == true
          read_timeout = @http_connect
          @initial_post = false
        elsif @previous_send == Time.at(0)
          read_timeout = @http_inactivity + 1
        else
          read_timeout = (Time.now - @previous_send).ceil + @http_inactivity
        end

        Jabber::debuglog("#{@protocol_name} REQUEST (#{@pending_requests + 1}/#{@http_requests}) with timeout #{read_timeout}:\n#{request.body}")
        begin
          response = @http.start(@uri.host, @uri.port, nil, nil, nil, nil ) do |http|
            http.read_timeout = read_timeout
            http.use_ssl = @use_ssl
            http.verify_mode = @verify_mode if @use_ssl # Allow caller to defeat certificate verify
            http.request(request)
          end
        rescue Timeout::Error => e
          message = "::post Timeout error in Net::HTTP " + e.message
          Jabber::debuglog message
          raise
        end
        Jabber::debuglog("#{@protocol_name} RESPONSE (#{@pending_requests + 1}/#{@http_requests}): #{response.class}\n#{response.body}")

        unless response.kind_of? Net::HTTPSuccess
          # Unfortunately, HTTPResponses aren't exceptions
          # TODO: rescue'ing code should be able to distinguish
          raise Net::HTTPBadResponse, "#{response.class}"
        end

        body = REXML::Document.new(response.body).root
        if body.name != 'body' and body.namespace != 'http://jabber.org/protocol/httpbind'
          raise REXML::ParseException.new('Malformed body')
        end
        body
      end

      ##
      # Prepare data to POST and
      # handle the result
      def post_data( data = '' )
        req_body = nil
        current_rid = nil

        begin
          begin
            @lock.synchronize {
              # Do not send unneeded requests
              @pending_requests += 1
              if data.size < 1 and @pending_requests > 1
                return
              end

              req_body = "<body"
              req_body += " rid='#{@http_rid += 1}'"
              req_body += " sid='#{@http_sid}'"
              req_body += " xmlns='http://jabber.org/protocol/httpbind'"
              
              # Want to be able to add attributes,
              # specifically for pause='xx' but maybe
              # for other things, too
              ( @body_attributes || [] ).each do |key, value|
                req_body += " #{ key }='#{ value }'"
              end
              unless data == ''
                req_body += " >"
                req_body += data
                req_body += "</body>"
              else
                req_body += "/>"
              end
              current_rid = @http_rid

              @previous_send = @last_send
              @last_send = Time.now

            }

            res_body = post(req_body)

          ensure
            @lock.synchronize { @pending_requests -= 1 }
          end

          receive_elements_with_rid(current_rid, res_body.children)
          ensure_one_pending_request

        rescue REXML::ParseException
          if @exception_block
            Thread.new do
              #Thread.current.abort_on_exception = true
              begin
                close; @exception_block.call(e, self, :parser)
              rescue
                Jabber::debuglog( "301 Exit!" )
                raise
              end
            end
          else
            Jabber::debuglog "Exception caught when parsing #{@protocol_name} response!"
            raise
          end

        # Shouldn't retry a 404... 
        # chances are if it's not there, now
        # it's not going to be there later.
        rescue Net::HTTPBadResponse => e
          Jabber::debuglog("POST error (did NOT retry, rescued): #{e.class}: #{e}")
          raise
        rescue Timeout::Error => e
          Jabber::debuglog("Timeout error (did NOT retry, rescued): #{e.class}: #{e}")
          raise
        rescue StandardError => e
          Jabber::debuglog("POST error (will retry): #{e.class}: #{e}")
          raise if @retry_error > 4
          receive_elements_with_rid(current_rid, [])
          # It's not good to resend on *any* exception,
          # but there are too many cases (Timeout, 404, 502)
          # where resending is appropriate
          # TODO: recognize these conditions and act appropriate
          send_data(data)
          @retry_error += 1
        end
      end

      ##
      # Send data,
      # buffered and obeying 'polling' and 'requests' limits
      def send_data(data)
        @lock.synchronize do

          @send_buffer += data
          limited_by_polling = (@last_send + @http_polling >= Time.now)
          limited_by_requests = (@pending_requests + 1 > @http_requests)

          # Can we send?
          if !limited_by_polling and !limited_by_requests
            data = @send_buffer
            @send_buffer = ''

            @post_num = 0
            Thread.new do
              Jabber::debuglog( "new thread: " + Thread.current.inspect )
              #Thread.current.abort_on_exception = true
              begin
                Jabber::debuglog( "post_num = " + @post_num.to_s ) if @post_num > 0
                Jabber::debuglog( "Reposting data" ) if @post_num > 0
                post_data(data)
                @post_num += 1
              rescue Net::HTTPBadResponse => e
                Jabber::debuglog("Bad Response, in thread " + Thread.current.inspect + " error (did NOT retry, rescued): #{e.class}: #{e}")
                raise
              rescue Timeout::Error => e
                Jabber::debuglog("Timeout, in thread " + Thread.current.inspect + " error (did NOT retry, rescued): #{e.class}: #{e}")
                raise
              rescue StandardError => e
                Jabber::debuglog("Standard Error, in thread " + Thread.current.inspect + " error (did NOT retry, rescued): #{e.class}: #{e}")
                raise
              end
            end

          elsif !limited_by_requests
            Thread.new do
              Thread.current.abort_on_exception = true
              begin
                # Defer until @http_polling has expired
                wait = @last_send + @http_polling - Time.now
                sleep(wait) if wait > 0
                # Ignore locking, it's already threaded ;-)
                send_data('')
              rescue Net::HTTPBadResponse => e
                Jabber::debuglog( "Thread: " + Thread.current + " " + e )
                raise
              rescue Timeout::Error => e
                Jabber::debuglog( "Thread: " + Thread.current + " " + e )
                raise
              rescue StandardError => e
                Jabber::debuglog( "Thread: " + Thread.current + " " + e )
                raise
              end
            end
          end

        end
      end
    end
  end
end
