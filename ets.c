/*
 ********************************************************
 * ets.c
 * EthernetType Statistics in C
 ********************************************************
 * Program description:
 * Read captured ethernet packets using the pcap library,
 * and then print out stats about IPv4, IPv6 or other.
 * 
 * Function description:
 * This C program could identify the following traffics:
 * 
 * - IPv4 frames
 * - IPv6 frames
 * - Other types of Ethernet traffic
 *
 ********************************************************
 * To compile: $ gcc -Wall -o ets_osx ets.c -l pcap -l ncurses
 * 
 * To run: sudo tcpdump -i en0 -p --immediate-mode -U -s14 -w - 2> /etc/null | ./ets_osx -
 *     Or: ./ets_osx <some file captured from tcpdump or wireshark>
 ******************************************************** 
 *
 * Made by Marco Davids, based on a lot of stuff from people
 * who are much smarter than me. 
 */

/* Libraries */
#include <time.h>
#include <math.h>		//for round()
#include <stdlib.h>		//malloc
#include <string.h>		//strlen
#include <signal.h>		//for SIGWINCH handler
#include <locale.h>		//format the numbers in printf
#include <ncurses.h>		//ncurses
#include <sys/socket.h>
#include <netinet/in.h>		//internet protocol family
#include </usr/include/pcap/pcap.h>	//pcap library
#include <netinet/if_ether.h>	//ethernet header declarations
//#include <netinet/ether.h>      //ethernet header declarations

/* Prototypes */
void handle_packet (u_char *, const struct pcap_pkthdr *, const u_char *);
int center (int row, char *title);
int drawgraph (int desiredrow);
void print_numbers (void);
void sigwinchHandler (int sig);
void sigintHandler (int sig);

/* Global Variables */
unsigned long long int tot_packet_counter = 0;	//total packet number
unsigned long long int tot_bytes_counter = 0;	//total bytes total
unsigned long long int ip_packet_counter = 0;	//ipv4 packet number
unsigned long long int ip_bytes_counter = 0;	//ipv4 bytes total
unsigned long long int ipv6_packet_counter = 0;	//ipv6 packet number
unsigned long long int ipv6_bytes_counter = 0;	//ipv6 bytes total
unsigned long long int other_packet_counter = 0;	//other packet number
unsigned long long int other_bytes_counter = 0;	//other bytes total
static volatile sig_atomic_t resizedwin = 0;	//SIGWINCH handler flag 
float ip_percentage = 0.0;	//percentage ipv4
float ipv6_percentage = 0.0;	//percentage ipv6
float other_percentage = 0.0;	//percentage other
int headerLength = 0;		//packet header length
int ip_bytes = 0;		//headerLength in IPv4 case
int ipv6_bytes = 0;		//headerLength in IPv4 case
int other_bytes = 0;		//headerLength in IPv4 case
pcap_t *handle;
uint16_t ethertype = 0;
time_t starttime;
time_t endtime;
char time_start[26];
char time_end[26];

/* Defines */
#define VERSION "1.02-20190212"

/* Main */
int
main (int argc, char *argv[])
{
  //setlocale (LC_NUMERIC, "nl_NL.ISO8859-15"); // printf("%'d\n", 1123456789); <-- hopefully becomes 1.123.456.789
  setlocale (LC_NUMERIC, "en_US.UTF-8");
  const char *fname = argv[1];		//pcap filename
  char errbuf[PCAP_ERRBUF_SIZE];	//error buffer

  //handle if pcap file is missing
  if (argc == 1)
    {
      printf ("Version: %s\n", VERSION);
      printf ("Usage: $./ets [captured_file_name] \n");
      printf ("   or: tcpdump [parameters] | ./ets\n");
      exit (EXIT_FAILURE);
    }

  //handle error if command is wrong
  if (argc > 2)
    {
      printf ("Error: unrecognized command! \n");
      printf ("Usage: $./ets [captured_file_name] \n");
      printf ("   or: tcpdump [parameters] | ./ets\n");
      exit (EXIT_FAILURE);
    }

  //open pacp file
  handle = pcap_open_offline (fname, errbuf);

  //if pacp file has errors
  if (handle == NULL)
    {
      printf ("pcap file [%s] with error %s \n", fname, errbuf);
      exit (EXIT_FAILURE);
    }

  // start ncurses

  //savetty(); // TODO doesn't help with restoring proper output at end of program
  initscr ();

  if ((LINES < 20) || (COLS < 100))
    {
      endwin ();
      printf ("Version: %s\n", VERSION);
      printf
	("This program requires a screen size of at least 100 columns by 20 lines\n"
	 "Please resize your window.\n");
      exit (EXIT_FAILURE);
    }

  // Own SIGWINCH signal handler 
  signal (SIGWINCH, sigwinchHandler);
  // Own SIGNINT signal handler
  signal (SIGINT, sigintHandler);
  // TODO could be combined in one handler: http://www.csl.mtu.edu/cs4411.ck/www/NOTES/signal/two-signals.html

  start_color ();
  curs_set (0);
  clear ();
  // IPv4
  init_pair (1, COLOR_RED, COLOR_BLACK);
  // IPv6
  init_pair (2, COLOR_GREEN, COLOR_BLACK);
  // Other
  init_pair (3, COLOR_MAGENTA, COLOR_BLACK);

  // TODO: give a color?
  mvprintw (2, 1, "Waiting for data...");

  attrset (COLOR_PAIR (2) | A_BOLD);
  center (1, " EtherType Statistics ");
  center (12, " Graph ");
  center (16, " Histogram (TODO) ");

  // Get starttime
  starttime = time (NULL);
  ctime_r (&starttime, time_start);

  //pacp loop to set our callback function
  //the work is done in handle_packet
  pcap_loop (handle, 0, handle_packet, NULL);

  getchar ();			// Primarily handy when pcap is not piped, but command-line parameter
  //while(getchar() != 27) {} /* 27 = Esc key */

  //attroff (COLOR_PAIR (1));   // TODO Needed, or...?
  //attroff (COLOR_PAIR (3));   // TODO Needed, or...?
  //attroff (COLOR_PAIR (3));   // TODO Needed, or...?
  pcap_close (handle);
  endwin ();
  printf ("\nBye.\n");
  return (EXIT_SUCCESS);
}

void
sigwinchHandler (int sig)
// Do as little as possible within the handler
{
  resizedwin = 1;
}

void
sigintHandler (int sig)
{
  pcap_close (handle);
  endwin ();
  // ANSI clear screen
  printf ("\e[1;1H\e[2J");
  // get endtime
  endtime = time (NULL);
  ctime_r (&endtime, time_end);
  printf ("\n-----------------------------\nSome closing stats:\n");
  printf
    ("IPv4 bytes: %'llu (%.3f %%), IPv6 bytes: %'llu (%.3f %%), other bytes: %'llu (%.3f %%).\n",
     ip_bytes_counter, ip_percentage, ipv6_bytes_counter, ipv6_percentage,
     other_bytes_counter, other_percentage);
  // An '\n' is added by ctime
  printf ("Starttime: %s", time_start);
  printf ("  Endtime: %s", time_end);
  printf ("Total number of packets: %'llu.\n", tot_packet_counter);
  printf ("IPv4: %'llu packets, IPv6: %'llu packets, Other: %'llu packets.\n",
	  ip_packet_counter, ipv6_packet_counter, other_packet_counter);
  printf ("Goodbye!\n");
  printf ("-----------------------------\n");
  exit (EXIT_SUCCESS);
}

/* Handle packet */
void
handle_packet (u_char * args, const struct pcap_pkthdr *header,
	       const u_char * packet)
{
  // Disadvantage; will only perform action when a new packet arrives
  if (resizedwin)
    {
      resizedwin = 0;
      endwin ();
      refresh ();
      clear ();
      attrset (COLOR_PAIR (2) | A_BOLD);
      center (1, " EtherType Statistics ");
      center (12, " Graph ");
      center (16, " Histogram (TODO) ");
    }

  //pointers to packet headers
  const struct ether_header *ethernet_header;	//ethernet header

  //get header length
  headerLength = header->len;

  //increase packet counter -> packet number
  ++tot_packet_counter;

  //define ethernet header
  ethernet_header = (struct ether_header *) (packet);

  //now, it's time to determine the traffic type and protocol type
  ethertype = ntohs (ethernet_header->ether_type);
  switch (ethertype)
    {
      // https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
      // https://github.com/wireshark/wireshark/blob/master/epan/etypes.h
      //IPv4 traffic
    case ETHERTYPE_IP:
      // TODO (unsigned long long int) needed?
      ip_bytes_counter += (unsigned long long int) headerLength;
      tot_bytes_counter += (unsigned long long int) headerLength;
      ++ip_packet_counter;
      ip_bytes = headerLength;
      ipv6_bytes = 0;
      other_bytes = 0;
      ethertype = 0;
      break;
      //IPv6
    case ETHERTYPE_IPV6:
      ipv6_bytes_counter += (unsigned long long int) headerLength;
      tot_bytes_counter += (unsigned long long int) headerLength;
      ++ipv6_packet_counter;
      ip_bytes = 0;
      ipv6_bytes = headerLength;
      other_bytes = 0;
      ethertype = 0;
      break;
      //Other traffic
    default:
      other_bytes_counter += (unsigned long long int) headerLength;
      tot_bytes_counter += (unsigned long long int) headerLength;
      ++other_packet_counter;
      ip_bytes = 0;
      ipv6_bytes = 0;
      other_bytes = headerLength;
      break;
    }
  print_numbers ();
}

void
print_numbers (void)
{
  // Do the math
  if (tot_bytes_counter > 0)
    {				// prevent devision by  0
      ip_percentage =
	((float) ip_bytes_counter / (float) tot_bytes_counter) * 100;
      ipv6_percentage =
	((float) ipv6_bytes_counter / (float) tot_bytes_counter) * 100;
      other_percentage =
	((float) other_bytes_counter / (float) tot_bytes_counter) * 100;
    };				// no else ip_percentage = 0 needed, I think
  // print the new numbers on screen
  attron (COLOR_PAIR (3) | A_BOLD);
  mvprintw (2, 1, "Total packets: [%'llu]", tot_packet_counter);
  // IPv4
  attron (COLOR_PAIR (1));
  mvprintw
    (4, 3,
     "IPv4  [packets: %'6llu]: (0x%04x) %'5d bytes (total v4:    %'6llu bytes, which is: %3.2f %%)     ",
     ip_packet_counter, ETHERTYPE_IP, ip_bytes, ip_bytes_counter,
     ip_percentage);
  // IPv6
  attron (COLOR_PAIR (2));
  mvprintw
    (6, 3,
     "IPv6  [packets: %'6llu]: (0x%04x) %'5d bytes (total v6:    %'6llu bytes, which is: %3.2f %%)     ",
     ipv6_packet_counter, ETHERTYPE_IPV6, ipv6_bytes, ipv6_bytes_counter,
     ipv6_percentage);
  // Other
  attron (COLOR_PAIR (3));
  mvprintw
    (8, 3,
     "Other [packets: %'6llu]: (0x%04x) %'5d bytes (total other: %'6llu bytes, which is: %3.2f %%)     ",
     other_packet_counter, ethertype, other_bytes, other_bytes_counter,
     other_percentage);
  attron (COLOR_PAIR (3) | A_BOLD);
  mvprintw (10, 1, "Total bytes: %'llu", tot_bytes_counter);
  drawgraph (13);
  drawgraph (14);
  drawgraph (15);
  refresh ();
}

int
center (int desiredrow, char *title)
{
  int len, indent, row, col, pos;

  getmaxyx (stdscr, row, col);

  if (desiredrow > row)
    return (EXIT_FAILURE);

  len = strlen (title);

  if (len > col)
    //exit (EXIT_FAILURE);
    return (EXIT_FAILURE);

  indent = (col - len) / 2;

  if (indent < 0)
    //exit (EXIT_FAILURE);
    return (EXIT_FAILURE);

  for (pos = 0; pos < indent - 1; pos++)
    mvaddch (desiredrow, pos, '-');

  addch ('[');

  mvaddstr (desiredrow, indent, title);
  mvaddch (desiredrow, pos + (len + 1), ']');

  for (pos += (len + 2); pos < col; pos++)
    mvaddch (desiredrow, pos, '-');

  refresh ();

  return (EXIT_SUCCESS);
}

int
drawgraph (int desiredrow)
{
  int row, col, pos;
  u_char ip, ipv6, other;

  getmaxyx (stdscr, row, col);

  if (desiredrow > row)
    return (EXIT_FAILURE);

  //mvprintw (17, 3, "Debug: col = %d", col);

  // Fit percentages in window
  ip = round (col * 0.01 * ip_percentage);
  ipv6 = round (col * 0.01 * ipv6_percentage);
  // Fill it up, instead of doing the formula again
  // TODO: somtimes shows a little bit more than justified (like one 'x' for only 0,10%)
  if (other_percentage > 0)
    other = col - (ip + ipv6);
  else
    other = 0;
  //other = round(col * 0.01 * other_percentage);

  //mvprintw (18, 3, "Debug: ip = %d, ipv6 = %d, other = %d", ip, ipv6, other);

  // Draw the line
  // IPv4
  attron (COLOR_PAIR (1));
  for (pos = 0; pos < ip; pos++)
    mvaddch (desiredrow, pos, '4');

  // IPv6
  attron (COLOR_PAIR (2));
  for (pos = 0; pos < ipv6; pos++)
    mvaddch (desiredrow, pos + ip, '6');

  // Other  
  attron (COLOR_PAIR (3));
  for (pos = 0; pos < other; pos++)
    mvaddch (desiredrow, pos + ip + ipv6, 'x');

  return (EXIT_SUCCESS);
}
