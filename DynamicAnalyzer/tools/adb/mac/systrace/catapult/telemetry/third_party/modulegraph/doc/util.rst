:mod:`modulegraph.util` --- Utilies functions
=============================================

.. module:: modulegraph.util
   :synopsis: Utilitie functions


.. function:: imp_find_module(name, path=None)

   This function has the same interface as
   :func:`imp.find_module`, but also works with
   dotted names.

.. function:: imp_walk(name)

   yields the namepart and importer information
   for every part of a dotted module name, and
   raises :exc:`ImportError` when the *name*
   cannot be found.

   The result elements are tuples with two
   elements, the first is a module name,
   the second is the result for :func:`imp.find_module`
   for that module (taking into account :pep:`302`
   importers)

   .. deprecated:: 0.10

.. function:: guess_encoding(fp)

   Returns the encoding of a python source file.
