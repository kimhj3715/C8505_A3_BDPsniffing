from distutils.core import setup
import py2exe

options = {
	"bundel_files" : 1,
	"compressed" :1,
	"optimize" : 2,
}

setup (
	console = ["bdClient.py"],
	options = {"py2exe" : options},
	zipfile = None
)