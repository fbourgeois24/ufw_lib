import subprocess
import yaml
import os

class Loader(yaml.SafeLoader):
	""" Custom loader, permet d'inclure des fichiers yaml depuis d'autres via !include """

	def __init__(self, stream):
		self._root = os.path.split(stream.name)[0]
		super(Loader, self).__init__(stream)

	def include(self, node):
		filename = os.path.join(self._root, self.construct_scalar(node))
		try:
			with open(filename, 'r') as f:
				return yaml.load(f, Loader)
		except FileNotFoundError:
			return ""

Loader.add_constructor('!include', Loader.include)

class yaml_parametres():
	""" Gestion des paramètres dans un fichier yaml externe
		Lors de l'initialisation de la fonction, read permet de directement lire les valeurs qui seront stockées dans self.content
		Dans ce cas les valeurs ne sont évidemment pas renvoyés sous forme de dictionnaire !
	 """
	def __init__(self, path, read=False):
		self.path = path
		self.content = {}
		if read:
			self.content = self.read()

	def read(self):
		""" Lire les paramètres et les stocker dans un dictionnaire
			Lors de l'exécution de cette fonction, les paramètres sont stockés dans self.content et sont renvoyés
		 """
		with open(self.path, "r") as yaml_file:
			dict_parameters = yaml.load(yaml_file, Loader=Loader)
		if dict_parameters is None:
			dict_parameters = {}
		
		self.content = dict_parameters
		return dict_parameters

def is_ip(addr):
	""" Regarde si l'adresse est une adresse ip et renvoie un booléen """
	if addr.count(".") != 3:
		return False
	bytes = addr.split(":")[0].split("/")[0].split(".")
	for byte in bytes:
		if not byte.isdigit():
			return False
	return True

def resolve_dn(dn):
	""" Résoudre un nom de domaine et renvoyer l'ip """
	dn = dn.split(':')[0]
	result = subprocess.run(f"ping {dn} -c 1", shell=True, capture_output=True)
	""" Codes de retour
		0 = OK
		1 = Résolution ok mais pas de ping
		2 = Pas de résolution
	"""
	if result.returncode <= 1:
		return result.stdout.decode().replace(f"PING {dn} (", '').split(')')[0]
	else:
		return None


def logger(name="main", existing=None, global_level=None, file_handler_level=10, stream_handler_level=10, 
	format='%(asctime)s | %(name)s:%(lineno)d [%(levelname)s] - %(message)s', stream_handler = True, file_handler = True, filename = "", file_handler_path = "./",
	remove_existing_handlers=False, http_handler_ip=None, http_handler_url="/logger/", http_handler_user="logger", http_handler_passwd="1234"):
	""" configurer un logger et renvoyer l'objet configuré
		name = nom du nouveau logger à créer
		existing = logger existant à configurer
		Niveaux de log (DEBUG, INFO, WARNING, ERROR ou CRITICAL)
			file_handler_level : niveau de log du fichier, par défaut DEBUG
			stream_handler_level : niveau de log de la console, par défaut DEBUG
			global_level = s'il est spécifié, il écrase les 2 précédents
		format = format des messages de log
		stream_handler = Vrai s'il faut l'activer
		file_handler = Vrai s'il faut l'activer
		filename = Nom du fichier de sortie (utilisé par exemple pour renvoyer la sortie des logger de différents modules vers le même fichier)

		http_handler_ip : ip:port
	"""

	import logging
	from logging.handlers import HTTPHandler

	if existing is not None:
		# Si un logger existant a été passé, on reprend son nom
		name = existing.name
	elif name == "":
		# Si pas de nom et pas de logger existant on lève une erreur
		raise TypeError("Au moins un nom (pour un nouveau logger) ou un logger existant doivent être passés en paramètre")
	
	if existing is None:
		# Si aucun logger existant n'a été passé, on en crée un nouveau
		log = logging.getLogger(name)
	else:
		# Si un logger existant a été passé on l'utilise
		log = existing
	if remove_existing_handlers:
		log.handlers = []
	# On définit le niveau de log du logger principal, il doit être égal au plus bas niveau tout handlers confondus
	if global_level is not None:
		level = global_level
	else:
		level = 1000 # Si pas définit il est mis très haut pour être sur qu'il ne soit pas le min
	log.setLevel(min((stream_handler_level, file_handler_level, level)))
	# Format des messages
	formatter = logging.Formatter(format)
	if filename == "" and name != "":
		# Si pas de nom de fichier fourni on utilise le nom
		filename = name + ".log"
	elif filename == "" and name == "":
		# Si pas de nom et pas de nom de fichier
		raise TypeError("Aucun nom ou nom de fichier fourni")
	elif len(filename.split(".")) < 2:
		# Si le nom de fichier n'a pas encore d'extension
		filename += ".log"
	if file_handler:	
		# Si un file_handler doit être ajouté
		file_handler = logging.FileHandler(file_handler_path + filename, encoding = "UTF-8")
		file_handler.setFormatter(formatter)
		if global_level is not None:
			file_handler.setLevel(global_level)
		else:
			file_handler.setLevel(file_handler_level)
		log.addHandler(file_handler)
	if stream_handler:	
		# Si un stream_handler doit être ajouté
		stream_handler = logging.StreamHandler()
		stream_handler.setFormatter(formatter)
		if global_level is not None:
			stream_handler.setLevel(global_level)
		else:
			stream_handler.setLevel(stream_handler_level)
		log.addHandler(stream_handler)
	if http_handler_ip is not None:
		# Si un http handler doit être ajouté
		http_handler = HTTPHandler(host=http_handler_ip, url=http_handler_url, method="POST", 
			credentials=(http_handler_user, http_handler_passwd))
		http_handler.setLevel(10)
		log.addHandler(http_handler)

	return log
