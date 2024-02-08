#!/usr/bin/python
# -*- coding: utf-8 -*-

""" 
Gestion du firewall ufw en standalone
Les ip et noms de domaines à autoriser sont enregistrés dans authorized.rules.
Les règles doivent tre au format ip:port ou nom:port
"""

import ufw_lib
from util_lib import *
import os, sys


# Si vrai aucune règle n'est réellement modifiée
if len(sys.argv) > 1 and sys.argv[0] == "apply":
	dry_run = False
else:
	dry_run = True
# Regarde si un changement a été appliqué
change = False

log = logger(name="firewall_manage")
if dry_run:
	log.warning("DRY RUN ACTIF. Aucune modifcation sera appliquée. Pour appliquer les modifications, ajoutez 'apply' en argument à l'appel")

ufw = ufw_lib.Ufw(do_checks=False)

# On regarde si ufw est actif, si pas on ne va pas plus loin
if not ufw.status().get("status") == "active":
	log.info("ufw inactif")
	exit()
log.info("ufw actif")

local_path = os.path.dirname(os.path.realpath(__file__)) + "/"

log.debug(f"Règles actives avant intervention : {ufw.get_rules()}")

# On lit les adresses et noms de domaine dans le fichier authorized.rules
with open(local_path + "authorized.rules", 'r') as rules_file:
	rules = rules_file.read().replace('\r', '').strip(" \n").split('\n')
log.debug(f"Règles à appliquer : {rules}")


# On résoud les noms de domaines
resolved_dn = {} # On stocke les noms résolus
for rule in rules[:]:
	addr, port = rule.split(":")
	if not is_ip(addr):
		# Si c'est un nom de domaine, on le remplace par son ip
		if addr not in resolved_dn:
			# Si nom pas encore résolu, on le résoud
			resolved_dn[addr] = resolve_dn(addr)
			log.debug(f"L'adresse ip du domaine '{addr}' est '{resolved_dn.get(addr)}'")
		if resolved_dn.get(addr) is not None:
			rules.remove(rule)
			rules.append(f"{resolved_dn.get(addr)}:{port}")
		else:
			log.critical(f"Erreur de résolution du nom de domaine {addr}")
			exit(1)

log.debug(f"Règles résolues : {rules}")

# On compare les règles actives aux données du fichier (noms de domaines résolus)
active_rules = ufw.get_rules()

# On parcours les règles du firewall pour trouver celles qui ne sont pas dans le fichier
for key, rule in active_rules.items():
	log.debug(f"Règle numéro {key}")
	rule_ip = ufw.rule_to_ip(rule)
	if rule_ip is None:
		log.error(f"Impossible de traduire la règle {rule} au format ip:port !")
		continue
	if not rule_ip in rules:
		log.debug(f"La règle {rule_ip} ne se trouve pas dans les règles approuvées, elle sera supprimée !")
		change = True
		if not dry_run:
			ufw.delete(rule)
	else:
		log.debug(f"La règle {rule_ip} se trouve dans les règles approuvées, elle sera conservée.")


# On cherche les règles à ajouter
active_rules = ufw.get_rules().values()
active_rules_ip = [ufw.rule_to_ip(rule) for rule in active_rules]

# On parcours les règles du fichier pour comparer à celles du firewall
for rule in rules:
	if rule not in active_rules_ip:
		# Si la règle n'est pas dans le firewall, on l'ajoute
		rule_detail = rule.split(":")
		rule_str = f"allow from {rule_detail[0]}"
		if len(rule_detail) > 1:
			# Le port a été spécifié
			rule_str += f" to any port {rule_detail[1]}"
		log.debug(f"La règle {rule} n'est pas encore dans le firewall, elle sera ajoutée : '{rule_str}'.")
		change = True
		if not dry_run:	
			ufw.add(rule_str)

	else:
		log.debug(f"La règle {rule} est déjà dans le firewall.")

if change:
	log.debug(f"Il y {'a eu' if not dry_run else 'aura'} au moins une modification de règle.")
else:
	log.debug("Aucune modification des règles")
if not dry_run:
	log.debug(f"Règles actives après intervention : {ufw.get_rules()}")