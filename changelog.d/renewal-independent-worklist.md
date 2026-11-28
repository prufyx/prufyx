### Security

- The renewal workflow now checks a signed statement against a worklist the signing job produces itself. Before, it compared the prepared worklist with itself. It refuses to continue without that worklist or when it is a copy of the prepared one.
