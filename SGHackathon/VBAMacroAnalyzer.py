import re
import ast


class VBAMacroAnalyzer:
	def __init__(self,vba_code):
		self.vba_code = vba_code
		self.parsed_code = self.parse_vba_code(vba_code)
		
	def parse_vba_code(self,code):
		lines = code.split('\n')
		structured_code = []
		
		for line in lines:
			line = line.strip()
			if line.startswith("") or line == "":
				continue
			structured_code.append(line)
		
		return structured_code
	def identify_inefficiencies(self):
		inefficiencies = []
		for line in self.parsed_code:
			if re.search(r'\bFor Each\b', line):
				inefficiencies.append(f"Potential inefficiency with 'For Each' loop: {line}")
			if re.search(r'\bSelect\b|\bActivate\b', line):
				inefficiencies.append(f"Potential inefficiency with 'Select' or 'Activate': {line}")
			if re.search(r'\bDoEvents\b', line):
				inefficiencies.append(f"Potential performance issue with 'DoEvents': {line}")
		
		return inefficiencies
    
	def suggest_optimizations(self):
		optimizations = []
        
		for line in self.parsed_code:
			if re.search(r'\bFor Each\b', line):
				optimizations.append(f"Consider using array operations instead of 'For Each' loop: {line}")
			if re.search(r'\bSelect\b|\bActivate\b', line):
				optimizations.append(f"Consider avoiding 'Select' or 'Activate' for better performance: {line}")

		return optimizations
    
	def evaluate(self):
		inefficiencies = self.identify_inefficiencies()
		optimizations = self.suggest_optimizations()
        
		return {
		'inefficiencies': inefficiencies,
		'optimizations': optimizations
		}
