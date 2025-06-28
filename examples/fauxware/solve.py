#!/usr/bin/env python

import angr
import claripy
import sys
import os
import random # Needed for picking a random seed and offset

# To disable some of angr's logging output (optional, useful for cleaner output)
import logging
logging.getLogger('angr').setLevel(logging.WARNING)


def retrive_all_basic_blocks(binary_path: str):
    """
    Retrieve all basic blocks in the program (using the binary loader or CFG)
    """
    all_basic_blocks = set()
    try:
        # Create a new project with auto_load_libs disabled
        p = angr.Project(binary_path, auto_load_libs=False)
        cfg = p.analyses.CFGFast()
        for node in cfg.nodes():
            all_basic_blocks.add(node.addr)
    except Exception as e:
        print(f"[!] Could not retrieve all basic blocks: {e}")
    return all_basic_blocks


def calculate_code_coverage(covered_blocks: set, total_blocks: set) -> float:
    if len(covered_blocks) == 0:
        print("[!] Warning: Covered Blocks is empty.")
        return 0.0
    
    # Sanity check: Ensure covered_blocks is a subset of total_blocks
    if not covered_blocks.issubset(total_blocks):
        print("[!] Warning: Some covered blocks are not in the total blocks set.")
        uncovered_blocks = covered_blocks - total_blocks
        print(f"[!] Uncovered blocks: {uncovered_blocks}")

    # Calculate coverage percentage
    coverage_percentage = (len(covered_blocks) / len(total_blocks)) * 100
    print(f"\n[*] Code Coverage: {coverage_percentage:.2f}%")
    print(f"[*] Total Basic Blocks: {len(total_blocks)}")
    print(f"[*] Covered Basic Blocks: {len(covered_blocks)}")
    return coverage_percentage


def filter_main_binary_blocks(project: angr.project, blocks: angr.state_plugins.history.LambdaIterIter) -> set:
    """
    Filter blocks to include only those from the main binary.
    Also, converts to a set for code coverage calculation.
    """
    main_binary = project.loader.main_object
    main_binary_start = main_binary.min_addr
    main_binary_end = main_binary.max_addr

    # Filter blocks within the main binary's address range
    filtered_blocks = {addr for addr in blocks if main_binary_start <= addr <= main_binary_end}
    return filtered_blocks


def perform_initial_concolic_exploration(initial_input_file: str = None, symbolic_bytes_count: int = 64):
    """
    Performs initial concolic execution using Angr on a binary, running until deadended states,
    and reports the basic block execution history for the explored paths.

    This version supports:
    1. Symbolic input content based on an initial concrete input file (hybrid approach).
    2. Dynamically setting the symbolic file size based on the initial input file's length.

    NOTE: This script assumes the 'fauxware' binary (or a similar LAVA binary)
    has been compiled from a C code that takes a single command-line argument which
    is the path to an input file.

    Args:
        initial_input_file (str, optional): Path to a concrete file to use as the base
                                            for symbolic input (for hybrid concolic execution).
                                            If None, a fully symbolic input is used.
        symbolic_bytes_count (int): Number of bytes to make symbolic in hybrid mode.
                                    Only relevant if initial_input_file is provided.
    """

    # Load the binary.
    # auto_load_libs=True ensures Angr's SimProcedures for library functions (like fopen, fread) are used.
    p = angr.Project('fauxware', auto_load_libs=True, load_debug_info=True)
    all_blocks = retrive_all_basic_blocks('fauxware')

    # Define the path for the symbolic input file within the simulated filesystem
    SYMBOLIC_FILE_PATH = '/tmp/input.txt'
    
    concrete_seed_content = b''
    actual_file_size = 0

    if initial_input_file and os.path.exists(initial_input_file):
        print(f"[*] Reading initial concrete input from: {initial_input_file}")
        with open(initial_input_file, 'rb') as f:
            concrete_seed_content = f.read()
        actual_file_size = len(concrete_seed_content)
        print(f"[*] Initial input file size: {actual_file_size} bytes.")
    else:
        print("[!] No valid initial input file provided. Falling back to a fully symbolic input.")
        # Default size if no concrete input is provided. A minimum size for useful exploration.
        actual_file_size = 64 

    # Determine the total size of the symbolic input.
    # It will be at least the size of the concrete seed (if provided), or a default size.
    total_symbolic_input_size = max(actual_file_size, symbolic_bytes_count) # Ensure enough space for symbolic part

    symbolic_file_content = None

    if concrete_seed_content:
        # Hybrid symbolic input:
        # Make a portion of the concrete input symbolic.
        
        # Ensure symbolic_bytes_count doesn't exceed the actual file size
        symbolic_bytes_to_make = min(symbolic_bytes_count, actual_file_size)

        # Choose a random offset within the concrete content to make symbolic
        # Ensure there's enough room for symbolic_bytes_to_make
        if actual_file_size > 0 and (actual_file_size - symbolic_bytes_to_make) >= 0:
            symbolic_start_offset = random.randint(0, actual_file_size - symbolic_bytes_to_make)
        else:
            symbolic_start_offset = 0 # If file is too small or symbolic_bytes_to_make is too large

        parts = []

        # Part 1: Concrete prefix
        if symbolic_start_offset > 0:
            parts.append(claripy.BVV(concrete_seed_content[:symbolic_start_offset]))
        
        # Part 2: Symbolic chunk
        symbolic_chunk = claripy.BVS(f'file_content_symbolic_{symbolic_start_offset}', symbolic_bytes_to_make * 8)
        parts.append(symbolic_chunk)
        
        # Part 3: Concrete suffix
        if (symbolic_start_offset + symbolic_bytes_to_make) < actual_file_size:
            parts.append(claripy.BVV(concrete_seed_content[symbolic_start_offset + symbolic_bytes_to_make:]))
        
        # Concatenate all parts to form the full symbolic content
        symbolic_file_content = claripy.Concat(*parts)
        
        print(f"[*] Hybrid symbolic input: {symbolic_bytes_to_make} bytes symbolic from offset {symbolic_start_offset}")
        print(f"    (Total input size based on initial file: {actual_file_size} bytes)")
    else:
        # Fully symbolic input (fallback or if no initial file is given)
        symbolic_file_content = claripy.BVS('file_content_full_symbolic', total_symbolic_input_size * 8)
        print(f"[*] Full symbolic input of size: {total_symbolic_input_size} bytes.")

    # Create a SimFile object with the (hybrid) symbolic content and dynamic size
    symbolic_sim_file = angr.SimFile(
        SYMBOLIC_FILE_PATH,
        content=symbolic_file_content,
        size=total_symbolic_input_size # Use the dynamically determined size
    )

    # Create the initial state.
    # We pass the binary path as argv[0] and our symbolic file path as argv[1].
    # We also inject our symbolic SimFile into the simulated filesystem (state.fs).
    state = p.factory.full_init_state(
        args=[p.filename, SYMBOLIC_FILE_PATH],
        fs={SYMBOLIC_FILE_PATH: symbolic_sim_file},
        # You can add Angr options here for performance, e.g.:
        pylgr_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
        # The user assumes initial inputs are OK and won't crash, so no special options needed here
    )

    # Initialize the SimulationManager with our state
    sm = p.factory.simulation_manager(state)

    #custom_tech = LAVAPrioritizingTechnique(
    #    project=p,
    #    priority_targets=target_addrs, # Add addresses of the deeply nested branch
    #    magic_values=magic_strings
    #)
    # sm.use_technique(custom_tech)

    print(f"[*] Starting symbolic execution until deadended states...")

    # Run the simulation manager until all active paths are exhausted (reach deadended states).
    sm.run()

    print(f"\n[*] Initial exploration complete. {len(sm.deadended)} deadended states found.")
    
    total_basic_blocks_covered = set()

    # Iterate through all deadended states and print their execution history
    for i, deadended_state in enumerate(sm.deadended):
        print(f"\n--- Path {i+1} ---")
        print(f"    Path terminated at address: {hex(deadended_state.addr)}")
        print(f"    Path History (Basic Block Addresses):")
        
        path_concrete_input = b''
        try:
            # Concretize the input that led to this specific deadended state
            path_concrete_input = deadended_state.solver.eval(symbolic_file_content, cast_to=bytes)
            print(f"    Input that led to this path: '{path_concrete_input}' (Hex: {path_concrete_input.hex()})")
            
            # Save the concretized input to a file
            output_dir = "concretized_inputs"
            os.makedirs(output_dir, exist_ok=True)  # Ensure the output directory exists

            # Generate a unique filename
            file_name = f"input_path{i+1}_{deadended_state.addr}.bin"  # Use the state's address or another unique identifier
            file_path = os.path.join(output_dir, file_name)

            # Write the concretized input to the file
            with open(file_path, "wb") as f:
                f.write(path_concrete_input)
            print(f"    Concretized input saved to: {file_path}")
            calculate_code_coverage(
                covered_blocks=filter_main_binary_blocks(p, deadended_state.history.bbl_addrs),
                total_blocks=all_blocks
            )
            
        except Exception as e:
            print(f"    Could not concretize input for this path: {e}")

        for addr in filter_main_binary_blocks(p, deadended_state.history.bbl_addrs):
            total_basic_blocks_covered.add(addr) # Track overall coverage
            line_info_str = ""
            try:
                line_info_str = ""
                # This will show source file, line number, and function if compiled with -g
                # print(p.loader.main_object.addr_to_line)
                # print(type(p.loader.main_object.addr_to_line))
                line_info = p.loader.main_object.addr_to_line[addr]
                #print("Show main_object", p.loader.main_object)
                #print("type", type(p.loader.main_object))
                #print("Available methods and attributes in main_object:")
                #for item in dir(p.loader.main_object):
                #    print(item)
                #print("SEction map, look for debug", p.loader.main_object.sections_map)

                if line_info:
                    file_path, line_num = next(iter(line_info))
                    # Format the line info string
                    if file_path and line_num:
                        line_info_str = f" ({os.path.basename(file_path)}:{line_num}"
            except KeyError:
                pass
            except Exception as e:
                print(f"[!] Exception occurred while retrieving line info: {e}")
                pass # Ignore if line info not found (e.g., in library code or no debug info)
            print(f"        - {hex(addr)}{line_info_str}")

        # Check if the backdoor message was printed in this specific path's stdout
        path_stdout = deadended_state.posix.dumps(1)
        if b'Welcome to the admin console, trusted user!' in path_stdout:
            print(f"    [+] Backdoor success message detected in stdout for this path!")
        elif b'Go away!' in path_stdout:
            print(f"    [-] 'Go away!' (rejected) message detected in stdout for this path.")
        else:
            print(f"    [?] No specific backdoor/rejected message detected in stdout for this path.")
        
        # You can add more checks here, e.g., if deadended_state.errored: print error details

    print(f"\n[*] Total unique basic blocks covered across all paths: {len(filter_main_binary_blocks(p, total_basic_blocks_covered))}")
    print(f"\n[*] Final coverage:",  calculate_code_coverage(
                covered_blocks=filter_main_binary_blocks(p, total_basic_blocks_covered),
                total_blocks=all_blocks
            ))
    print(f"[*] Raw deadended states: {sm.deadended}") # For debugging/inspection if needed
    
    # Return the simulation manager so we can continue exploration in the next step
    return sm, symbolic_file_content, p


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Perform initial concolic exploration and report path history.")
    parser.add_argument("--input-file", "-i", type=str, 
                        help="Path to an initial concrete input file to base symbolic input on.")
    parser.add_argument("--symbolic-bytes", "-s", type=int, default=64,
                        help="Number of bytes to make symbolic in the input file (for hybrid mode). Default: 64")
    args = parser.parse_args()

    dummy_input_path = "dummy_seed.txt"
    input_file_to_use = args.input_file
    
    # Check if a dummy file needs to be created because no input file was provided by the user
    create_dummy_file = False
    if args.input_file is None:
        create_dummy_file = True
        input_file_to_use = dummy_input_path # Set to dummy path for the function call
        with open(dummy_input_path, "wb") as f:
            f.write(b"A" * 32) # Write some dummy content
        print(f"[*] Created a dummy input file: {dummy_input_path}")

    # Call the main exploration function
    # We now return the simgr, symbolic_file_content, and project for potential future steps
    simgr_result, symbolic_content_var, project_obj = perform_initial_concolic_exploration(
        initial_input_file=input_file_to_use,
        symbolic_bytes_count=args.symbolic_bytes
    )
    
    # Example of how you might continue from here in a future step:
    # If you want to find a backdoor *after* the initial run:
    # find_condition = lambda s: b'Welcome to the admin console, trusted user!' in s.posix.dumps(1)
    # simgr_result.explore(find=find_condition)
    # ... then process simgr_result.found as before

    # Clean up the dummy file if it was created during this run
    if create_dummy_file and os.path.exists(dummy_input_path):
        os.remove(dummy_input_path)

