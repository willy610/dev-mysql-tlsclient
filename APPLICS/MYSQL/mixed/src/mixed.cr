require "db"
require "mysql"
require "tlsclient"
require "shared"
require "librfc8439"


# cd /Users/willys4/Documents/MYCRYSTAL/AAA/APPLICS/MYSQL/mixed/lib/mysql
# crystal tool unreachable src/mysql.cr
# crystal tool dependencies src/mysql.cr
# 
# Affects sql auth
# alter user 'kallelocal'@'localhost' identified by 'mimmi1947!';

module Mixed
  VERSION = "0.1.0"

  tests = [["mysql://root:soren@localhost/information_schema", "select table_name,column_name from columns WHERE TABLE_NAME like('events_waits_hi%') "],
           ["mysql://test:blabla@192.168.50.126/information_schema?tls=skip-verify", "select table_name,column_name from columns WHERE TABLE_NAME like('events_waits_hi%')"],
           ["mysql://root:soren@localhost/chrisdate", "select * from S"],
           ["mysql://root:soren@192.168.50.126/chrisdate?tls=skip-verify", "select * from S"],
           ["mysql://test:test@localhost/chrisdate", "select * from S"], # good for full caching_sha2_password
           ["mysql://root:soren@localhost/chrisdate", "select * from S"],
           ["mysql://root:soren@localhost/chrisdate?encoding=utf8mb4_0900_ai_ci", "select * from S"],
           ["mysql://kallelocal:mimmi1947!@localhost/chrisdate", "select * from S"],
           ["mysql://root:soren@192.168.50.126/chrisdate", "select * from S"],
           ["mysql://root:soren@192.168.50.126/chrisdate?tls=skip-verify", "select * from S"],
           ["mysql://test:blabla@192.168.50.126/information_schema?tls=skip-verify", "select table_name,column_name from columns limit 4000"],
           ["mysql://ett:ett@192.168.50.126/chrisdate?tls=skip-verify", "select * from S"],
  ]
  the_url, stm = tests[1]

  if ARGV.size == 1
    i = ARGV[0].to_i
    the_url = tests[i][0]
    stm = tests[i][1]
  elsif ARGV.size == 2
    puts ARGV[0]
    puts ARGV[1]
    # i = 0
    the_url = ARGV[0]
    stm = ARGV[1]
  else
    i = 0
    the_url = tests[i][0]
    stm = tests[i][1]
  end
  puts the_url
  puts stm
  # begin
  DB.open the_url do |db|
    res3 = db.query stm do |rs|
      puts "+ #{rs.column_name(0)} + #{rs.column_name(1)} +"
      rs.each do
        puts "| #{rs.read(String)} | #{rs.read(String)} |"
      end
    end
  end

  # rescue e
  #   puts "sorry #{e}"
  # end

end
