#!/usr/bin/python
# -*- coding: utf-8 -*-

import ufw_lib
from util_lib import yaml_parametres, logger, is_ip, resolve_dn
import os
import db_unified

# Si vrai aucune règle n'est réellement modifiée
dry_run = False
# Regarde si un changement a été appliqué
change = False

log = logger(name="firewall_manage")

ufw = ufw_lib.Ufw(do_checks=False)

# On regarde si ufw est actif, si pas on ne va pas plus loin
if not ufw.status().get("status") == "active":
	log.info("ufw inactif")
	exit()
log.info("ufw actif")

local_path = os.path.dirname(os.path.realpath(__file__)) + "/"
secrets = yaml_parametres(local_path + "local_secrets.yaml", read=True).content
db = db_unified.db_unified(config=secrets["database"]["gesmat"])

log.debug(f"Règles actives avant intervention : {ufw.get_rules()}")

# On lit les adresses et noms de domaine dans la db
rules = db.exec(''' SELECT valeur FROM parametres WHERE contexte = 'firewall' AND nom LIKE 'allow%' ''', fetch='list')
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

# On compare les règles actives aux données de la db (noms de domaines résolus)
active_rules = ufw.get_rules()

# On parcours les règles du firewall pour trouver celles qui ne sont pas dans la db
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

# On parcours les règles de la db pour comparer à celles du firewall
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
log.debug(f"Règles actives après intervention : {ufw.get_rules()}")