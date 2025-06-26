#!/usr/bin/env python

import angr
import claripy
import sys
import os
import random # Needed for picking a random seed and offset

# To disable some of angr's logging output (optional, useful for cleaner output)
import logging
logging.getLogger('angr').setLevel(logging.WARNING)

def find_backdoor_via_file_input(initial_input_file: str = None, symbolic_bytes_count: int = 64):
    """
    Demonstrates how to use Angr for concolic execution to find the 'SOSNEAKY' backdoor string
    when it's expected to be found within the *content* of a file provided as a command-line argument.

    This version supports:
    1. Symbolic input content based on an initial concrete input file (hybrid approach).
    2. Dynamically setting the symbolic file size based on the initial input file's length.

    NOTE: This script assumes the 'fauxware' binary (or a similar LAVA binary)
    has been compiled from a C code where:
    1. It takes a single command-line argument which is the path to an input file.
    2. It reads the content of this input file.
    3. The 'SOSNEAKY' backdoor is triggered if the *content of this file* matches "SOSNEAKY"
       or leads to a state that prints "Welcome to the admin console, trusted user!".
    (The original fauxware.c does not directly do this; its backdoor is via stdin 'password').

    Args:
        initial_input_file (str, optional): Path to a concrete file to use as the base
                                            for symbolic input (for hybrid concolic execution).
                                            If None, a fully symbolic input is used.
        symbolic_bytes_count (int): Number of bytes to make symbolic in hybrid mode.
                                    Only relevant if initial_input_file is provided.
    """

    # Load the binary.
    # auto_load_libs=True ensures Angr's SimProcedures for library functions (like fopen, fread) are used.
    p = angr.Project('fauxware', auto_load_libs=True)

    # Define the path for the symbolic input file within the simulated filesystem
    SYMBOLIC_FILE_PATH = '/tmp/input.txt'
    
    concrete_seed_content = b''
    actual_file_size = 0

    input_file_provided_by_user = (initial_input_file is not None)

    if initial_input_file and os.path.exists(initial_input_file):
        print(f"[*] Reading initial concrete input from: {initial_input_file}")
        with open(initial_input_file, 'rb') as f:
            concrete_seed_content = f.read()
        actual_file_size = len(concrete_seed_content)
        print(f"[*] Initial input file size: {actual_file_size} bytes.")
    else:
        print("[!] No valid initial input file provided. Falling back to a fully symbolic input.")
        # Default size if no concrete input is provided. SOSNEAKY is 8 bytes.
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
        # pylgr_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    )

    # Initialize the SimulationManager with our state
    sm = p.factory.simulation_manager(state)

    print(f"[*] Starting symbolic execution to find backdoor via file input...")

    # Define the find condition:
    # We want to find a state where the backdoor's success message appears in stdout.
    # The modified fauxware.c prints "Welcome to the admin console, trusted user! (via file backdoor)\n"
    # when the backdoor is triggered.
    find_condition = lambda s: b'Welcome to the admin console, trusted user!' in s.posix.dumps(1) # Check stdout (fd 1)

    # Explore until a state satisfying the find_condition is found.
    sm.explore(find=find_condition)

    # Check if any states were found that meet our condition
    if sm.found:
        print(f"\n[+] Found {len(sm.found)} state(s) where the backdoor message was detected in output!")
        
        # Take the first found state
        found_state = sm.found[0]
        
        # Concretize the content of the symbolic file
        try:
            # Evaluate the full symbolic_file_content based on the found_state's constraints
            concrete_input = found_state.solver.eval(symbolic_file_content, cast_to=bytes)
            # Trim null bytes from the end if they are just padding for the symbolic part
            # Be careful with rstrip if actual nulls are meaningful data in your format.
            # For this example, it's generally safe.
            concrete_input = concrete_input.rstrip(b'\x00') 

            print(f"[*] Concretized input file content that triggers the backdoor: '{concrete_input}'")
            print(f"    (Hex: {concrete_input.hex()})")

            # Verify that SOSNEAKY is indeed in the concrete input, if applicable to your backdoor trigger
            # The backdoor in fauxware.c checks for "SOSNEAKY" directly in the input file content.
            if b'SOSNEAKY' in concrete_input:
                print("[+] 'SOSNEAKY' successfully found within the generated input bytes!")
            else:
                # This message indicates that while the backdoor was triggered (because "Welcome..." was printed),
                # the *exact string* "SOSNEAKY" wasn't directly present in the concretized input.
                # This could happen if the program transforms the input, or the trigger is more complex
                # than a direct string match (e.g., hash comparison, mathematical condition).
                # For our modified fauxware, it *should* contain SOSNEAKY.
                print("[-] 'SOSNEAKY' was not directly found in the generated input file content. This is unexpected for modified fauxware.")
                print("    Please verify that the generated input makes the strcmp('SOSNEAKY', input) return 0.")
                # For debug: print the full output of the state
                # print("Full stdout of found state:\n", found_state.posix.dumps(1))

            return concrete_input

        except Exception as e:
            print(f"[-] Error concretizing input: {e}")
            return None
    else:
        print("[-] No state found that prints the backdoor success message to stdout. The backdoor may not have been triggered by file content.")
        return None

def test():
    # To run this test, you'd need a 'test_input.txt' and a modified 'fauxware'
    # that reads the file content for the backdoor check.
    # For instance, create a 'test_input.txt' file with some content.
    test_file_path = "test_input.txt" 
    with open(test_file_path, "w") as f:
        f.write("A short test string here.")

    r = find_backdoor_via_file_input(initial_input_file=test_file_path, symbolic_bytes_count=8)
    
    # This assertion will only pass if your 'fauxware' (or a new binary) is
    # compiled to read the file and the backdoor is triggered by 'SOSNEAKY'
    # within that file, AND Angr correctly finds it.
    assert r is not None and b'SOSNEAKY' in r
    
    # Clean up test file
    os.remove(test_file_path)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Find backdoor via symbolic file input.")
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

    result_input = find_backdoor_via_file_input(
        initial_input_file=input_file_to_use,
        symbolic_bytes_count=args.symbolic_bytes
    )
    
    if result_input:
        output_filename = "backdoor_file_input.bin"
        with open(output_filename, "wb") as f:
            f.write(result_input)
        print(f"\nSuccessfully generated and saved input to: {output_filename}")
        print("To test this input (assuming a modified fauxware that takes a file arg):")
        print(f"Run with: ./fauxware {output_filename}")
    else:
        print("\nFailed to find backdoor input.")

    # Clean up the dummy file if it was created during this run
    if create_dummy_file and os.path.exists(dummy_input_path):
        os.remove(dummy_input_path)
