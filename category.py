import re
import urlparse

class Categorizor(object):
	def __init__(self, category_rule):
		"""category_rule is a string of the format:
		type:parameter:modifier

		To get the base64 decoded value of the category querystring 
		parameter, use:

		"querystring:category:base64"
		"""
		self.rule = category_rule.split(':')

	def categorize(self, final_url):
		if self.rule[0] == 'querystring':
			try:
				qs = urlparse.parse_qs(urlparse.urlparse(final_url).query)
				param = qs[self.rule[1]][0]
				if len(self.rule) == 3:
					if self.rule[2] == 'base64':
						param = param.decode('base64')
				return param
			except (KeyError,IndexError):
				return None
			
		
