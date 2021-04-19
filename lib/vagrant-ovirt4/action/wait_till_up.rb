require 'ipaddr'
require 'log4r'
require 'vagrant-ovirt4/util/timer'
require 'vagrant/util/retryable'
require 'socket'
require 'timeout'

module VagrantPlugins
  module OVirtProvider
    module Action

      # Wait till VM is started, till it obtains an IP address and is
      # accessible via ssh.
      class WaitTillUp
        include Vagrant::Util::Retryable

        def initialize(app, env)
          @logger = Log4r::Logger.new("vagrant_ovirt4::action::wait_till_up")
          @app = app
        end

        def port_open?(ip, port, seconds=10)
          # => checks if a port is open or not on a remote host
          Timeout::timeout(seconds) do
            begin
              TCPSocket.new(ip, port).close
              @logger.info("SSH Check OK for IP: #{ip}")
              true
            rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, SocketError => e
              @logger.info("SSH Connection Failed for IP #{ip}: #{e}")
              false
            end
          end
          rescue Timeout::Error
            @logger.info("SSH Connection Failed: Timeout for IP: #{ip}" )
            false
        end

        def call(env)
          # Initialize metrics if they haven't been
          env[:metrics] ||= {}

          # Get config.
          config = env[:machine].provider_config

          # Wait for VM to obtain an ip address.
          env[:metrics]["instance_ip_time"] = Util::Timer.time do
            env[:ui].info(I18n.t("vagrant_ovirt4.waiting_for_ip"))
            env[:ui].detail(I18n.t("vagrant_ovirt4.waiting_for_ip_timeout", :count => config.ip_addr_timeout.to_f))
            Timeout::timeout(config.ip_addr_timeout) do
              loop do
                # If we're interrupted don't worry about waiting
                return if env[:interrupted]

                # Get VM.
                server = env[:vms_service].vm_service(env[:machine].id)
                if server == nil
                  raise Errors::NoVMError, :vm_id => env[:machine].id
                end

                nics_service = server.nics_service
                nics = nics_service.list
                begin
                  ip_addr = nics.collect { |nic_attachment| env[:connection].follow_link(nic_attachment.reported_devices).collect { |dev| dev.ips.collect { |ip| ip.address if ip.version == 'v4' } unless dev.ips.nil? } }.flatten.reject { |ip| ip.nil? }.first
                rescue
                  # for backwards compatibility with ovirt 4.3
                  ip_addr = nics.collect { |nic_attachment| env[:connection].follow_link(nic_attachment).reported_devices.collect { |dev| dev.ips.collect { |ip| ip.address if ip.version == 'v4' } unless dev.ips.nil? } }.flatten.reject { |ip| ip.nil? }.first rescue nil
                end

                if ip_addr
                  begin
                    IPAddr.new(ip_addr)
                    # Check if SSH-Server is up
                    if port_open?(ip_addr, 22)
                      env[:ip_address] = ip_addr
                      @logger.debug("Got output #{env[:ip_address]}")
                      break
                    end
                  rescue IPAddr::InvalidAddressError
                    @logger.warn("Invalid IP address returned: #{ip_addr}")
                  end
                end

                sleep 1
              end

              return if env[:interrupted]

              if env[:ip_address]
                env[:ui].detail("IP: #{env[:ip_address]}")
                @logger.info("Got IP address #{env[:ip_address]}")
                # Booted and ready for use.
                env[:ui].info(I18n.t("vagrant_ovirt4.ready"))

                @app.call(env)
              else
                raise Errors::NoIPError
              end
            rescue Timeout::Error
              raise Errors::NoIPError
            end
          end
          @logger.info("Time for getting IP: #{env[:metrics]["instance_ip_time"]}")
        end
      end
    end
  end
end

