import gettext
import os

import ufw.frontend
import ufw.common
import ufw.parser
import ufw.util


class Ufw():

    def __init__(self, do_checks=True):
        """ do_checks fait des vérifications de sécurité
            is setuid or setgid (for non-Linux systems)
            checks that script is owned by root
            checks that every component in absolute path are owned by root
            warn if script is group writable
            warn if part of script path is group writable
            Possibilité de les désactiver en mettant le paramètre à False
        """

        self._init_gettext()

        if not do_checks:
            ufw.common.do_checks = False

        self.frontend = ufw.frontend.UFWFrontend(dryrun=False)
        self.backend = self.frontend.backend

        
    def _init_gettext(self):
        progName = ufw.common.programName
        # Due to the lack of _ method (of gettext module) in builtins namespace, some methods used in ufw fail
        gettext.install(progName)  # fixes '_' not defined. Performs builtins.__dict__['_'] = self.gettext according to https://github.com/python/cpython/blob/3.9/Lib/gettext.py


    def _update_ufw_dependencies(self):  # When the state is changed externaly (i.e. another python program), a previous frontend instance does not detect the changes
        self._init_gettext()
        frontend = ufw.frontend.UFWFrontend(dryrun=False)
        return frontend, frontend.backend


    def _run_rule(self, rule_str, force=True):
        
        self._init_gettext()

        p = ufw.parser.UFWParser()

        # Rule commands
        for i in ['allow', 'limit', 'deny' , 'reject', 'insert', 'delete']:
            p.register_command(ufw.parser.UFWCommandRule(i))
            p.register_command(ufw.parser.UFWCommandRouteRule(i))

        pr = p.parse_command(rule_str.split(' '))

        rule = pr.data.get('rule', '') 
        ip_type = pr.data.get('iptype', '')

        return self.frontend.do_action(pr.action, rule, ip_type, force)


    def enable(self):
        self._init_gettext()
        self.frontend.set_enabled(True)


    def disable(self):
        self._init_gettext()
        self.frontend.set_enabled(False)


    def reset(self):
        self._init_gettext()

        prior_state = self.backend.is_enabled()
        if prior_state:
            self.frontend.set_enabled(False)

        resp = self.backend.reset()

        self.backend.defaults = None
        self.backend.rules = []
        self.backend.rules6 = []

        self.backend._get_defaults()
        self.backend._read_rules()

        # 'ufw reset' doesn't appear to reset the default policies???? weird
        # We'll set theses defaults then instead
        self.default(incoming='deny', outgoing='allow', routed='reject')

        if prior_state:
            self.frontend.set_enabled(True)

        return resp


    def reload(self):
        self._init_gettext()
        # Only reload if ufw is enabled
        if self.backend.is_enabled():
            self.frontend.set_enabled(False)
            self.frontend.set_enabled(True)


    def set_logging(self, level):
        self._init_gettext()
        if not level in('on', 'off', 'low', 'medium', 'high', 'full'):
            raise ufw.common.UFWError('Logging level must be one of: on, off, medium, high, full')

        self.frontend.set_loglevel(level)


    def default(self, incoming=None, outgoing=None, routed=None, force=True):
        self._init_gettext()
        for direction in ('incoming', 'outgoing', 'routed'):
            policy = locals()[direction]
            if not policy: continue
            if not policy in ('allow', 'deny', 'reject'):
                raise ufw.common.UFWError('Policy must be one of: allow, deny, reject')

            self.backend.set_default_policy(policy, direction)

        if self.backend.is_enabled():
            self.backend.stop_firewall()
            self.backend.start_firewall()


    def add(self, rule, number=None, force=True):
        self._init_gettext()
        
        if not rule.startswith(('allow', 'deny', 'reject', 'limit', 'route')):
            raise ufw.common.UFWError('Rule must start with one of: allow, deny, reject, limit, route')

        if rule.startswith('route'):
            if not number:
                self._run_rule(rule, force=force)
            else:
                rule_parts = rule.split(' ')
                rule_parts.insert(1, 'insert {}'.format(number))
                rule = ' '.join(rule_parts)
                self._run_rule(rule, force=force)
        else:
            if not number:
                self._run_rule("rule {}".format(rule), force=force)
            else:
                self._run_rule("rule insert {} {}".format(number, rule), force=force)


    def delete(self, rule, force=True):
        self._init_gettext()

        try:
            rule = int(rule)
        except: pass

        if type(rule) == int:
            self.frontend.delete_rule(rule, force=force)
        elif rule == "*":
            number_of_rules = len(self.get_rules())
            for _ in range(number_of_rules):
                self.frontend.delete_rule(1, force=force)
        else:
            if rule.split(' ')[0] == 'route':
                self._run_rule("route delete {}".format(rule), force=force)
            else:
                self._run_rule("rule delete {}".format(rule), force=force)


    def _get_enabled(self):
        self._init_gettext()

        for direction in ["input", "output", "forward"]:
            # Is the firewall loaded at all?
            (rc, out) = ufw.util.cmd([self.backend.iptables, '-L', 'ufw-user-%s' % (direction), '-n'])
            if rc == 1:
                return False
            elif rc != 0:
                raise ufw.common.UFWError("iptables: {}\n".format(out))
        return True


    def status(self):
        self._init_gettext()
        frontend, backend = self._update_ufw_dependencies()  # Backend is not storing some changes that happen outside this program => create a new instance to get the last state

        if not self._get_enabled():
            status = {'status': 'inactive'}
        else:
            status = {
                'status': 'active',
                'default': {
                    'incoming': backend._get_default_policy(),
                    'outgoing': backend._get_default_policy('output'),
                    'routed': backend._get_default_policy('forward')
                },
                'rules': self.get_rules()
            }
        return status


    def get_rules(self):
        self._init_gettext()
        frontend, backend = self._update_ufw_dependencies()  # Backend is not storing some changes that happen outside this program => create a new instance to get the last state

        rules = backend.get_rules()
        count = 1
        app_rules = {}
        return_rules = {}
        for r in rules:

            if r.dapp != "" or r.sapp != "":
                tupl = r.get_app_tuple()

                if tupl in app_rules:
                    continue
                else:
                    app_rules[tupl] = True

            if r.forward:
                rstr = "route {}".format(ufw.parser.UFWCommandRouteRule.get_command(r))
            else:
                rstr = ufw.parser.UFWCommandRule.get_command(r)
                
            return_rules[count] = rstr
            count += 1
        return return_rules


    def show_raw(self):
        self._init_gettext()
        return self.frontend.get_show_raw('raw')


    def show_builtins(self):
        self._init_gettext()
        return self.frontend.get_show_raw('builtins')


    def show_before_rules(self):
        self._init_gettext()
        return self.frontend.get_show_raw('before-rules')


    def show_user_rules(self):
        self._init_gettext()
        return self.frontend.get_show_raw('user-rules')


    def show_logging_rules(self):
        self._init_gettext()
        return self.frontend.get_show_raw('logging-rules')


    def show_listening(self):
        self._init_gettext()

        try:
            netstat = ufw.util.parse_netstat_output(self.backend.use_ipv6())
        except Exception:
            #Could not get listening status
            return

        listeners = []
        rules = self.backend.get_rules()
        l4_protocols = list(netstat.keys())
        l4_protocols.sort()
        for transport in l4_protocols:
            if not self.backend.use_ipv6() and transport in ['tcp6', 'udp6']: continue

            ports = list(netstat[transport].keys())
            ports.sort()
            for port in ports:
                for item in netstat[transport][port]:

                    listen_addr = item['laddr']

                    if listen_addr.startswith("127.") or listen_addr.startswith("::1"):
                        continue

                    ifname = ""
                    if listen_addr == "0.0.0.0" or listen_addr == "::":
                        listen_addr = "%s/0" % (item['laddr'])
                        addr = "*"
                    else:
                        ifname = ufw.util.get_if_from_ip(listen_addr)
                        addr = listen_addr

                    application = os.path.basename(item['exe'])

                    rule = ufw.common.UFWRule(action="allow",
                                                protocol=transport[:3],
                                                dport=port,
                                                dst=listen_addr,
                                                direction="in",
                                                forward=False
                                                )
                    rule.set_v6(transport.endswith("6"))

                    if ifname != "":
                        rule.set_interface("in", ifname)
                    rule.normalize()

                    matching_rules = {}
                    matching = self.backend.get_matching(rule)
                    if len(matching) > 0:
                        for rule_number in matching:
                            if rule_number > 0 and rule_number - 1 < len(rules):
                                rule = self.backend.get_rule_by_number(rule_number)
                                rule_command = ufw.parser.UFWCommandRule.get_command(rule)
                                matching_rules[rule_number] = rule_command

                    listeners.append((transport, addr, int(port), application, matching_rules))
        return listeners


    def show_added(self):
        return self.get_rules()

    def rule_to_ip(self, rule):
        """ Converti une règle en format ip:port 
            Exemples de sytaxe prise en charge
            - allow 22 => 0.0.0.0:22
            - allow from 0.0.0.0 => 0.0.0.0
            - allow from 0.0.0.0 to any port 23 => 0.0.0.0:23
        """
        rule_elements = rule.split(" ")
        
        if rule_elements[1].isdigit():
            # Si le port est en 2e position
            return "0.0.0.0:" + rule_elements[1]

        elif rule_elements[1] == "from":
            # l'élément suivant est l'ip
            ip = rule_elements[2]

            if len(rule_elements) == 3:
                # Le port n'a pas été spécifié
                return ip
            else:
                # Le port a été spécifié
                return f"{ip}:{rule_elements[6]}"

        return None
