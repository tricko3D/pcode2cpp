# @runtime PyGhidra
"""Export one previously analyzed Ghidra function as a complete JSON context.

Arguments: <absolute_output.json> <hexadecimal_function_entry>
Invoked by pcode2cpp. The project must already be analyzed; optional PDB/type imports
must be applied in Ghidra first. No project mutations are made here.
"""

import json

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.data import Array, Composite, Enum, Pointer, TypeDef


def address_text(address):
    if address is None:
        return None
    if address.isMemoryAddress():
        return "0x%x" % address.getUnsignedOffset()
    return str(address)


def source_text(source):
    return str(source) if source is not None else "UNKNOWN"


def get_type(dtype):
    if dtype is None:
        return None
    return {"name": str(dtype.getDisplayName()), "path": str(dtype.getPathName()), "size": int(dtype.getLength())}


def describe_variable(var):
    return {
        "name": str(var.getName()),
        "type": get_type(var.getDataType()),
        "storage": str(var.getVariableStorage()),
        "source": source_text(var.getSource()),
    }


def describe_function(fn):
    if fn is None:
        return None
    info = {
        "name": str(fn.getName(True)),
        "address": address_text(fn.getEntryPoint()),
        "signature": str(fn.getSignature(True)),
        "calling_convention": str(fn.getCallingConventionName()),
        "source": source_text(fn.getSymbol().getSource()) if fn.getSymbol() else "UNKNOWN",
        "external": bool(fn.isExternal()),
        "thunk": bool(fn.isThunk()),
    }
    if fn.isThunk():
        target = fn.getThunkedFunction(True)
        info["ultimate_thunk_target"] = address_text(target.getEntryPoint()) if target else None
    return info


def varnode_data(vn):
    if vn is None:
        return None
    out = {"storage": str(vn), "size": int(vn.getSize()), "address": address_text(vn.getAddress())}
    hv = vn.getHigh()
    if hv is not None:
        out["high_name"] = str(hv.getName())
        out["high_type"] = get_type(hv.getDataType())
    return out


def collect_types(dtypes):
    """Definitions of referenced types (including nested layouts), with recursion safety."""
    definitions = {}

    def visit(dt, depth=0):
        if dt is None:
            return
        info = get_type(dt)
        key = info["path"]
        if key in definitions or depth > 6:
            return
        if len(definitions) >= 512:
            raise RuntimeError("Too many referenced types; inspect this function manually")
        entry = dict(info)
        entry["kind"] = dt.getClass().getSimpleName()
        definitions[key] = entry
        if isinstance(dt, Composite):
            fields = []
            for part in dt.getComponents():
                child = part.getDataType()
                fields.append({
                    "offset": int(part.getOffset()),
                    "length": int(part.getLength()),
                    "name": str(part.getFieldName()) if part.getFieldName() else None,
                    "type": get_type(child),
                    "comment": str(part.getComment()) if part.getComment() else None,
                })
                visit(child, depth + 1)
            entry["fields"] = fields
        elif isinstance(dt, Enum):
            entry["values"] = [{"name": str(n), "value": int(dt.getValue(n))} for n in dt.getNames()]
        elif isinstance(dt, TypeDef):
            entry["underlying"] = get_type(dt.getBaseDataType())
            visit(dt.getBaseDataType(), depth + 1)
        elif isinstance(dt, Pointer):
            entry["points_to"] = get_type(dt.getDataType())
            visit(dt.getDataType(), depth + 1)
        elif isinstance(dt, Array):
            entry["element_type"] = get_type(dt.getDataType())
            entry["elements"] = int(dt.getNumElements())
            visit(dt.getDataType(), depth + 1)

    for dtype in dtypes:
        visit(dtype)
    return sorted(definitions.values(), key=lambda x: x["path"])


def export_one(program, entry, monitor):
    fm = program.getFunctionManager()
    f = fm.getFunctionAt(entry)
    if f is None:
        raise RuntimeError("No function starts at %s; specify its entry address" % address_text(entry))
    dec = DecompInterface()
    options = DecompileOptions()
    options.grabFromProgram(program)
    dec.setOptions(options)
    dec.openProgram(program)
    try:
        result = dec.decompileFunction(f, 120, monitor)
        if not result.decompileCompleted() or result.getHighFunction() is None:
            raise RuntimeError("Ghidra decompilation failed: " + str(result.getErrorMessage()))
        pseudocode = result.getDecompiledFunction().getC()
        high = result.getHighFunction()
        pcode = []
        dtypes = [f.getReturnType()]
        dtypes.extend(v.getDataType() for v in f.getParameters())
        dtypes.extend(v.getDataType() for v in f.getLocalVariables())
        high_vars = {}
        for op in high.getPcodeOps():
            seq = op.getSeqnum()
            operands = [varnode_data(op.getInput(i)) for i in range(op.getNumInputs())]
            output = varnode_data(op.getOutput())
            for node in [op.getOutput()] + [op.getInput(i) for i in range(op.getNumInputs())]:
                if node is not None and node.getHigh() is not None:
                    hv = node.getHigh()
                    high_vars[str(hv.getName()) + ":" + str(hv.getDataType().getPathName())] = {
                        "name": str(hv.getName()), "type": get_type(hv.getDataType())
                    }
                    dtypes.append(hv.getDataType())
            pcode.append({
                "address": address_text(seq.getTarget()),
                "order": int(seq.getTime()),
                "operation": str(op.getMnemonic()),
                "output": output,
                "inputs": operands,
                "block_index": int(op.getParent().getIndex()) if op.getParent() is not None else None,
            })
        blocks = []
        for b in high.getBasicBlocks():
            blocks.append({
                "index": int(b.getIndex()),
                "start": address_text(b.getStart()),
                "end": address_text(b.getStop()),
                "successors": [int(b.getOut(i).getIndex()) for i in range(b.getOutSize())],
            })
        listing = program.getListing()
        references = program.getReferenceManager()
        symbols = program.getSymbolTable()
        assembly, calls, globals_ = [], [], []
        seen_globals = set()
        for ins in listing.getInstructions(f.getBody(), True):
            addr = ins.getAddress()
            assembly.append({
                "address": address_text(addr),
                "instruction": str(ins),
                "bytes": "".join("%02x" % (int(b) & 255) for b in ins.getBytes()),
            })
            refs = list(references.getReferencesFrom(addr))
            call_refs = [r for r in refs if r.getReferenceType().isCall()]
            if ins.getFlowType().isCall():
                if not call_refs:
                    calls.append({
                        "site": address_text(addr), "target": None,
                        "resolution": "unresolved_indirect_or_unreferenced",
                        "instruction": str(ins), "callee": None,
                    })
                for ref in call_refs:
                    dest = ref.getToAddress()
                    callee = fm.getFunctionAt(dest)
                    if callee:
                        dtypes.append(callee.getReturnType())
                        dtypes.extend(p.getDataType() for p in callee.getParameters())
                    calls.append({
                        "site": address_text(addr), "target": address_text(dest),
                        "resolution": "direct_reference" if dest.isMemoryAddress() else "external_reference",
                        "reference_source": source_text(ref.getSource()),
                        "instruction": str(ins), "callee": describe_function(callee),
                    })
            for ref in refs:
                if not ref.getReferenceType().isData():
                    continue
                dest = ref.getToAddress()
                if not dest.isMemoryAddress() or str(dest) in seen_globals:
                    continue
                seen_globals.add(str(dest))
                symbol = symbols.getPrimarySymbol(dest)
                data = listing.getDataAt(dest)
                if data:
                    dtypes.append(data.getDataType())
                globals_.append({
                    "address": address_text(dest),
                    "symbol": str(symbol.getName(True)) if symbol else None,
                    "symbol_source": source_text(symbol.getSource()) if symbol else None,
                    "data_type": get_type(data.getDataType()) if data else None,
                    "reference_source": source_text(ref.getSource()),
                    "read": bool(ref.getReferenceType().isRead()),
                    "write": bool(ref.getReferenceType().isWrite()),
                })
        if not pcode or not assembly:
            raise RuntimeError("Incomplete Ghidra analysis (missing P-code or assembly)")
        return {
            "schema_version": 1,
            "program": {
                "name": str(program.getName()),
                "language": str(program.getLanguageID()),
                "compiler_spec": str(program.getCompilerSpec().getCompilerSpecID()),
                "image_base": address_text(program.getImageBase()),
                "note": "Symbols/types are current Ghidra database values; IMPORTED does not prove PDB provenance or retail accuracy",
            },
            "function": {
                **describe_function(f),
                "end": address_text(f.getBody().getMaxAddress()),
                "return_type": get_type(f.getReturnType()),
                "parameters": [describe_variable(v) for v in f.getParameters()],
                "locals": [describe_variable(v) for v in f.getLocalVariables()],
            },
            "pseudocode": str(pseudocode),
            "high_pcode": pcode,
            "basic_blocks": blocks,
            "assembly": assembly,
            "calls": calls,
            "globals": globals_,
            "variables": sorted(high_vars.values(), key=lambda x: x["name"]),
            "types": collect_types(dtypes),
        }
    finally:
        dec.dispose()


def main():
    args = getScriptArgs()
    if len(args) != 2:
        raise ValueError("Usage: export_function.py <output.json> <hex_function_entry>")
    output_path, function_address = args
    space = currentProgram.getAddressFactory().getDefaultAddressSpace()
    entry = space.getAddress(int(function_address, 16))
    context = export_one(currentProgram, entry, monitor)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(context, fh, indent=2, sort_keys=True, ensure_ascii=False)
    println("pcode2cpp exported %s (%d P-code operations, %d calls)" % (
        function_address, len(context["high_pcode"]), len(context["calls"])))


if __name__ == "__main__":
    main()
