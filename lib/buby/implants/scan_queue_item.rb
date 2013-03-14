class Buby
  module Implants

    # This interface is used to retrieve details of items in the Burp Scanner
    # active scan queue. Extensions can obtain references to scan queue items by
    # calling {Buby#doActiveScan}.
    #
    module ScanQueueItem

      # This method returns details of the issues generated for the scan queue
      # item. 
      # @note different items within the scan queue may contain duplicated
      #   versions of the same issues - for example, if the same request has
      #   been scanned multiple times. Duplicated issues are consolidated in the
      #   main view of scan results. Extensions can register a
      #   {Buby::ScannerListener} to get details only of unique, newly
      #   discovered Scanner issues post-consolidation.
      #
      # @return [Array<IScanIssue>] Details of the issues generated for the scan
      #   queue item.
      #
      def getIssues
        __getIssues.tap{|issues| Buby::ScanIssueHelper.implant issues.first}
      end

      # Install ourselves into the current +IScanQueueItem+ java class
      # @param [IScanQueueItem] item
      #
      def self.implant(item)
        unless item.implanted? || item.nil?
          pp [:implanting, item, item.class] if $DEBUG
          item.class.class_exec(item) do |item|
            a_methods = %w{
              getIssues
            }
            a_methods.each do |meth|
              alias_method "__"+meth.to_s, meth
            end
            include Buby::Implants::ScanQueueItem
            a_methods.each do |meth|
              java_class.ruby_names_for_java_method(meth).each do |ruby_meth|
                define_method ruby_meth, Buby::Implants::ScanQueueItem.instance_method(meth)
              end
            end
            include Buby::Implants::Proxy
          end
        end
        item
      end
      
    end
  end
end