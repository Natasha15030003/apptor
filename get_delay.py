import StringIO
import time
import pycurl
import stem.control
from stem.descriptor.remote import DescriptorDownloader
from stem.descriptor.router_status_entry import RouterStatusEntryV3
import pdb
from stem.descriptor import parse_file
import stem.process
from stem.util import term


GUARD_FINGERPRINT = 'F65E0196C94DFFF48AFBF2F5F9E3E19AAE583FD0'
MIDDLE_FINGERPRINT = '0519D312F1BD9668B3B43751E0934911E4C79C79'

SOCKS_PORT = 9050
CONNECTION_TIMEOUT = 30  # timeout before we give up on a circuit

#####Get Top 100 relays with most bandwidth#########################



def get_top_100_relays():
"""Get Top 100 relays with the most bandwidth weights"""

  downloader = DescriptorDownloader(
    use_mirrors = True,
    timeout = 10,
  )

  query = downloader.get_consensus()
  router_bandwidth = {}
  router_bandwidth_sorted = {}

  i = 0

  for desc in query.run():

    router_bandwidth[i] = [desc.fingerprint, desc.exit_policy, desc.bandwidth]
    #pdb.set_trace()
    i=i+1

  i=0
  sorted_relays = []
  for key, value in sorted(router_bandwidth.items(), key = lambda fun: fun[1][2], reverse = True):

    sorted_relays.insert(i, [value[0], value[1], value[2]]) 
    #pdb.set_trace()
	i = i+1


  sorted_exit_relays = []
  i = 0

  for item in sorted_relays:
  #pdb.set_trace()
  	if item[1].is_exiting_allowed() == True:

      sorted_exit_relays.insert(i, item[0]) ## get the fingerprint if exiting allowed
	  i = i+1

  return sorted_exit_relays 



################################

def query(url):

  """

  Uses pycurl to fetch a site using the proxy on the SOCKS_PORT.

  """

  output = StringIO.StringIO()



  query = pycurl.Curl()
  query.setopt(pycurl.URL, url)
  query.setopt(pycurl.PROXY, 'localhost')
  query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
  query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
  query.setopt(pycurl.CONNECTTIMEOUT, CONNECTION_TIMEOUT)
  query.setopt(pycurl.WRITEFUNCTION, output.write)

  try:

  	query.perform()
	return output.getvalue()

  except pycurl.error as exc:

    raise ValueError("Unable to reach %s (%s)" % (url, exc))





def scan(controller, path):

  """

  Fetch check.torproject.org through the given path of relays, providing back

  the time it took.

  """



  circuit_id = controller.new_circuit(path, await_build = True)



  def attach_stream(stream):

    if stream.status == 'NEW':

      controller.attach_stream(stream.id, circuit_id)



  controller.add_event_listener(attach_stream, stem.control.EventType.STREAM)



  try:

    controller.set_conf('__LeaveStreamsUnattached', '1')  # leave stream management to us

    start_time = time.time()



    check_page = query('https://check.torproject.org/')



    if 'Congratulations. This browser is configured to use Tor.' not in check_page:

      raise ValueError("Request didn't have the right content")



    return time.time() - start_time

  finally:

    controller.remove_event_listener(attach_stream)

    controller.reset_conf('__LeaveStreamsUnattached')





with stem.control.Controller.from_port() as controller:



  controller.authenticate()

  

  top_100_fingerprints = get_top_100_relays() # get fingerprints of top 100 exit nodes



  i = 0

  time_taken = []  

  

  for fingerprint in top_100_fingerprints:

    try:

      time_taken.insert(i,scan(controller, [GUARD_FINGERPRINT, MIDDLE_FINGERPRINT, fingerprint]))

      i=i+1

      #time_taken = scan(controller, [fingerprint, EXIT_FINGERPRINT])

      print('%s => %0.2f seconds' % (fingerprint, time_taken))

    except Exception as exc:

      print('%s => %s' % (fingerprint, exc))
