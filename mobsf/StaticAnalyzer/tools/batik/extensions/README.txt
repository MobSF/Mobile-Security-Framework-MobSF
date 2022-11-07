The Jar files in this directory start the same application as in the
parent directory, except they include the Batik Extensions on the jar
file class path.  This means that that the Batik Extensions will work
with the applications started by these jar files.

Great care should be used when using the Batik Extensions as these are
not part of the SVG standard.  If you write content that uses these
extensions you must be aware that this is not conformant SVG content
and other SVG renderers will not render these documents.  These
extensions should only be used in content used in closed systems.

The primary purpose of these extensions is demonstrative and to
generate feedback to the development of the SVG standard.
