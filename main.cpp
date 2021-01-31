#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "include/pka2xml.hpp"

bool opt_exists(char *begin[], char *end[], const std::string &option) {
  return std::find(begin, end, option) != end;
}

void die(const char *message) {
  std::fprintf(stderr, "%s", message);
  std::exit(1);
}

void help()
{
  std::printf(R"(usage: pka2xml [ options ]

where options are:
  -d <in> <out>   decrypt pka/pkt to xml
  -e <in> <out>   encrypt pka/pkt to xml

  -f <in> <out>   allow packet tracer file to be read by any version

  -nets <in>      decrypt packet tracer "nets" file
  -logs <in>      decrypt packet tracer log file

  --forge <out>   forge authentication file to bypass login


examples:
  pka2xml -d foobar.pka foobar.xml
  pka2xml -e foobar.xml foobar.pka
  pka2xml -nets $HOME/packettracer/nets
  pka2xml -logs $HOME/packettracer/pt_12.05.2020_21.07.17.338.log
)");
  std::exit(1);
}

int main(int argc, char *argv[]) {
  if (argc == 1) {
    help();
  }

#ifdef HAS_UI
  if (argc > 1 && std::string(argv[1]) == "gui") {
    QApplication app(argc, argv);
    Gui gui{};
    gui.show();
    return app.exec();
  }
#endif

  // TODO graceful error checking
  try {
    if (argc > 3 && opt_exists(argv, argv + argc, "-d")) {
      std::ifstream f_in{argv[2]};
      if (!f_in.is_open()) {
        die("error opening input file");
      }
      std::string input{std::istreambuf_iterator<char>(f_in), std::istreambuf_iterator<char>()};
      f_in.close();
      std::ofstream f_out{argv[3]};
      if (!f_out.is_open()) {
        die("error opening output file");
      }
      f_out << pka2xml::decrypt_pka(input);
      f_out.close();
    } else if (argc > 3 && opt_exists(argv, argv + argc, "-e")) {
      std::ifstream f_in{argv[2]};
      if (!f_in.is_open()) {
        die("error opening input file");
      }
      std::string input{std::istreambuf_iterator<char>(f_in), std::istreambuf_iterator<char>()};
      f_in.close();
      std::ofstream f_out{argv[3]};
      if (!f_out.is_open()) {
        die("error opening output file");
      }
      f_out << pka2xml::encrypt_pka(input);
      f_out.close();
    } else if (argc > 2 && opt_exists(argv, argv + argc, "-logs")) {
      std::ifstream f_in{argv[2]};
      if (!f_in.is_open()) {
        die("error opening input file");
      }
      std::string line;
      while (std::getline(f_in, line)) {
        std::cout << pka2xml::decrypt_logs(line) << std::endl;
      }
      f_in.close();
    } else if (argc > 2 && opt_exists(argv, argv + argc, "-nets")) {
      std::ifstream f_in{argv[2]};
      if (!f_in.is_open()) {
        die("error opening input file");
      }
      std::string input{std::istreambuf_iterator<char>(f_in), std::istreambuf_iterator<char>()};
      std::cout << pka2xml::decrypt_nets(input) << std::endl;
      f_in.close();
    } else if (argc > 2 && opt_exists(argv, argv + argc, "--forge")) {
      std::ofstream f_out{argv[2]};
      f_out << pka2xml::encrypt_nets("foobar~foobar~foobar~foobar~1700000000");
      f_out.close();
    } else if (argc > 3 && opt_exists(argv, argv + argc, "-f")) {
      std::ifstream f_in{argv[2]};
      if (!f_in.is_open()) {
        die("error opening input file");
      }
      std::string input{std::istreambuf_iterator<char>(f_in), std::istreambuf_iterator<char>()};
      f_in.close();
      std::ofstream f_out{argv[3]};
      f_out << pka2xml::fix(input);
      f_out.close();
    } else {
      help();
    }
  } catch (int err) {
    die("error during the processing of the files, make sure the input files are valid");
  }
}
