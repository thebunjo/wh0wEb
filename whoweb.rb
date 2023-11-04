require 'whois'
require 'colorize'
require 'net/http'
require 'resolv'

def banner
  banner_text = <<-'BANNER'
                            .-'''-.                                               
                           '   _    \                                             
                 .       /   /` '.   \                   __.....__     /|         
       _     _ .'|      .   |     \  '       _     _ .-''         '.   ||           
 /\    \\   //<  |      |   '      |  '/\    \\   ///     .-''"'-.  `. ||         
 `\\  //\\ //  | |      \    \     / / `\\  //\\ ///     /________\   \||  __     
   \`//  \'/   | | .'''-.`.   ` ..' /    \`//  \'/ |                  |||/'__ '.  
    \|   |/    | |/.'''. \  '-...-'`      \|   |/  \    .-------------'|:/`  '. ' 
     '         |  /    | |                 '        \    '-.____...---.||     | | 
               | |     | |                           `.             .' ||\    / ' 
               | |     | |                             `''-...... -'   |/\'..' /  
               | '.    | '.                                            '  `'-'`   
               '---'   '---'       
  ---------------------------- Author: Bunjo ---------------------------------    
-------------------- Github: https://github.com/thebunjo -----------------------                                        
  BANNER

  puts banner_text.cyan
end

def check_firewall(url)
  url1 = URI.parse(url)
  response = Net::HTTP.get_response(url1)

  server_header = response['Server']
  puts "Server Header: #{server_header}"
end

def dns_enum(domain)
  resolver = Resolv::DNS.new

  begin

    nameservers = resolver.getresources(domain, Resolv::DNS::Resource::IN::NS)
    puts "Nameservers for #{domain}:"
    nameservers.each do |ns|
      puts "  #{ns.name}"
    end

    mx_records = resolver.getresources(domain, Resolv::DNS::Resource::IN::MX)
    puts "MX records for #{domain}:"
    mx_records.each do |mx|
      puts "  #{mx.exchange} (priority #{mx.preference})"
    end

    a_records = resolver.getresources(domain, Resolv::DNS::Resource::IN::A)
    puts "A records for #{domain}:"
    a_records.each do |a|
      puts "  #{a.address}"
    end

    cname_records = resolver.getresources(domain, Resolv::DNS::Resource::IN::CNAME)
    puts "CNAME records for #{domain}:"
    cname_records.each do |cname|
      puts "  #{cname.name}"
    end

  rescue Resolv::ResolvError => e
    puts "Error resolving DNS records for #{domain}: #{e}"
  end
end

def subdomain_resolver(target)
  resolver = Resolv::DNS.new

  subdomains = []
  resolver.each_resource(target, Resolv::DNS::Resource::IN::NS) do |resource|
    subdomains << resource.name.to_s
  end

  if subdomains.any?
    puts "Subdomains found for #{target}:"
    subdomains.each { |subdomain| puts subdomain }
  else
    puts "No subdomains found for #{target}."
  end
end

def reverse_ip_scan(ip)
  puts "Reverse IP Scanner Results for IP: #{ip}"
  resolver = Resolv::DNS.new

  begin
    ptr_results = resolver.getresources(ip, Resolv::DNS::Resource::IN::PTR)
    ptr_results.each do |ptr|
      puts ptr.name.to_s
    end
  rescue Resolv::ResolvError
    puts "No PTR records found for IP: #{ip}"
  end
end

def send_request(url, prt)
  url2 = URI.parse(url)
  http = Net::HTTP.new(url2.host, prt)
  request = Net::HTTP::Get.new(url)

  response = http.request(request)

  puts "HTTP Response Code: #{response.code}"
  puts "HTTP Response Text: #{response.message}"
  puts "HTTP Response Body:"
  puts response.body
end

def banner_grabber(host, port)
  s = TCPSocket.open(host, port)

  s.puts("GET / HTTP/1.1\r\n\r\n")

  while line = s.gets
    puts line.chop
  end
  s.close
end

def find_whois(url)
  whois_client = Whois::Client.new
  result = whois_client.lookup(url)

  if result.available?
    puts "Domain '#{url}' is available.".red
  else
    output = "Domain Name: #{result.properties["Domain Name"]}\n" \
      "Registrar: #{result.properties["Registrar"]}\n" \
      "Registrant: #{result.properties["Registrant"]}\n" \
      "Created Date: #{result.properties["Creation Date"]}\n" \
      "Updated Date: #{result.properties["Updated Date"]}\n" \
      "Expires Date: #{result.properties["Expiration Date"]}"

    puts output
  end
rescue Whois::Error => e
  puts "Whois Error: #{e.message}".red
rescue StandardError => e
  puts "Error: #{e.message}".red
end

def find_ip_address(url)
  ip_address = Socket.getaddrinfo(url, nil, Socket::AF_INET)
  return ip_address[0][3]
rescue
  puts "{!} Something went wrong."
end

def options
  puts "{1} - Website IP Finder".colorize(:yellow).bold
  puts "{2} - Website Whois Information".colorize(:yellow)
  puts '{3} - Website Send "GET" Request'.colorize(:green).bold
  puts "{4} - Website TCP Port Scanner".colorize(:green)
  puts "{5} - DNS Enumeration".colorize(:magenta).bold
  puts "{6} - Banner Grabber (HTTP/GET)".colorize(:magenta)
  puts "{7} - Reverse IP Scanner".colorize(:cyan).bold
  puts "{8} - Subdomain Resolver".colorize(:cyan)
  puts "{9} - Website Firewall Header Scan".colorize(:red)
  puts "{99} - Exit Program".colorize(:red).bold
end

def clear_screen
  system Gem.win_platform? ? 'cls' : 'clear'
end

def get_options
  print "\nwh0wEb >  ".colorize(:blue).bold.underline
  opt = gets.chomp.to_i

  if opt.to_s.empty?
    clear_screen
    puts "Invalid input. Please enter a valid option.".red
    return get_options
  end

  case opt

  when 99 # Exit
    puts "Bye!".red
    exit(0)

  when 1 # IP Finder
    while true
      print 'Enter Target Domain (Press "q" for return): '.yellow.bold
      inpt_url = gets.chomp
      if inpt_url == "q"
        clear_screen
        break
      else
        ip_result = find_ip_address(inpt_url)
        puts "[+] Result: #{ip_result}".green.bold
        inpt_url = ""
      end
    end

  when 2 # Whois
    while true
      print 'Enter Target Domain (Press "q" for return): '.yellow.bold
      inpt_url = gets.chomp
      if inpt_url == "q"
        clear_screen
        break
      else
        find_whois(inpt_url)
        inpt_url = ""
      end
    end

  when 3 # Send Get Request
    while true
      print 'Enter Target URL (ex: https://example.com ) (Press "q" for return): '.yellow.bold
      inpt_url = gets.chomp
      if inpt_url == "q"
        clear_screen
        break
      else
        print 'Enter Port: '.yellow.bold
        port = gets.chomp.to_i
        send_request(inpt_url, port)
        inpt_url = ""
      end
    end

  when 4 # Port Scan
    while true
      print 'Enter Target Domain (Press "q" for return): '.yellow.bold
      trgt = gets.chomp
      if trgt == "q"
        clear_screen
        break
      else
        print "Enter Ports (ex: 21,22,3306): ".cyan.bold
        ports = gets.chomp
        port_list = ports.split(',')

        $threads = []

        port_list.each do |port|
          $threads << Thread.new do
            begin
              $socket = TCPSocket.new(trgt, port.to_i)
              puts "{+} Port #{port} is open.".green.bold
            rescue
              puts "{-} Port #{port} is closed/filtered.".red.bold
            ensure
              $socket.close if $socket
            end
          end

          $threads.each(&:join)
        end
      end
    end

  when 5 # Dns Enumeration
    while true
      print 'Enter Target Domain (Press "q" for return): '.yellow.bold
      inpt_url = gets.chomp
      if inpt_url == "q"
        clear_screen
        break
      else
        dns_enum(inpt_url)
        inpt_url = ""
      end
    end

  when 6 # Banner Grabber
    while true
      print 'Enter Target Host (Press "q" for return): '.yellow.bold
      inpt_url = gets.chomp
      if inpt_url == "q"
        clear_screen
        break
      else
        print "Enter Port: ".cyan.bold
        port = gets.chomp.to_i
        banner_grabber(inpt_url, port)
        inpt_url = ""
      end
    end

  when 7 # Reverse IP Scanner
    while true
      print 'Enter Target IP Address (Press "q" for return): '.yellow.bold
      target_ip = gets.chomp
      break if target_ip == "q"

      reverse_ip_scan(target_ip)
    end

  when 8 # Subdomain Resolver
    while true
      print 'Enter Target Domain (Press "q" for return): '.yellow.bold
      inpt_url = gets.chomp
      if inpt_url == "q"
        clear_screen
        break
      else
        subdomain_resolver(inpt_url)
        inpt_url = ""
      end
    end

  when 9 # Firewall
    while true
      print 'Enter Target URL (ex: https://www.example.com/) (Press "q" for return): '.yellow.bold
      inpt_url = gets.chomp
      if inpt_url == "q"
        break
      else
        check_firewall(inpt_url)
      end
    end
  else
    clear_screen
    puts "Invaild selection!".red.bold
  end
end

while true
  banner
  options
  get_options
end
