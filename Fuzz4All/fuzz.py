"""Main script to run the fuzzing process."""

import os
import time

import click
from rich.traceback import install

install()

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)

from Fuzz4All.make_target import make_target_with_config
from Fuzz4All.target.target import Target
from Fuzz4All.util.util import load_config_file


def is_ollama_model(model_name):
    return model_name.startswith("ollama/") or model_name in ["llama2", "starcoder"]


def write_to_file(fo, file_name):
    try:
        with open(file_name, "w", encoding="utf-8") as f:
            f.write(fo)
    except:
        pass


# === NEW HELPER FUNCTION FOR SELF-CORRECTION ===
def attempt_repair(target, code, error_msg):
    """
    Asks the LLM to fix the code based on the error message.
    """
    try:
        # Construct a C-style prompt for repair
        # We wrap the error in comments so the model understands context
        prompt = (
            f"/* The following C code failed to compile. */\n"
            f"{code}\n\n"
            f"/* The compiler output was: */\n"
            f"/* {str(error_msg).strip()} */\n\n"
            f"/* Please generate the fixed, complete C code below: */\n"
        )

        # Generate 1 repair candidate
        # We use a slightly lower temperature (0.6) to encourage correctness over creativity
        repairs = target.model.generate(
            prompt, 
            batch_size=1, 
            temperature=0.6, 
            max_length=1024
        )
        
        if repairs and len(repairs) > 0:
            return repairs[0]
            
    except Exception as e:
        # If the model call fails for any reason, fail silently and return None
        # print(f"[DEBUG] Repair failed: {e}")
        pass
    
    return None
# ===============================================


def fuzz(
    target: Target,
    number_of_iterations: int,
    total_time: int,
    output_folder: str,
    resume: bool,
    otf: bool,
):
    target.initialize()
    with Progress(
        TextColumn("Fuzzing • [progress.percentage]{task.percentage:>3.0f}%"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
    ) as p:
        task = p.add_task("Fuzzing", total=number_of_iterations)
        count = 0
        start_time = time.time()

        if resume:
            n_existing = [
                int(f.split(".")[0])
                for f in os.listdir(output_folder)
                if f.endswith(".fuzz")
            ]
            n_existing.sort(reverse=True)
            if len(n_existing) > 0:
                count = n_existing[0] + 1
            log = f" (resuming from {count})"
            p.console.print(log)

        p.update(task, advance=count)

        while (
            count < number_of_iterations
            and time.time() - start_time < total_time * 3600
        ):
            fos = target.generate()
            if not fos:
                target.initialize()
                continue
            prev = []
            for index, fo in enumerate(fos):
                file_name = os.path.join(output_folder, f"{count}.fuzz")
                write_to_file(fo, file_name)
                
                # We need to increment count here normally, but wait...
                # If we repair, we might want to overwrite or save as a variant.
                # For simplicity, we overwrite the current slot if repair succeeds.
                
                # validation on the fly
                f_result_final = None # Placeholder
                if otf:
                    f_result, message = target.validate_individual(file_name)
                    
                    # === ALGORITHM CHANGE 1: SELF-CORRECTION LOGIC ===
                    # Heuristic: If "error:" is in the message, it's a compile error.
                    # We only fix compile errors, not runtime crashes (which are good bugs!).
                    if "error:" in str(message).lower():
                        # Try to repair
                        repaired_code = attempt_repair(target, fo, message)
                        
                        if repaired_code:
                            # Save repaired code to a .repaired file first
                            file_name_repaired = file_name + ".repaired"
                            write_to_file(repaired_code, file_name_repaired)
                            
                            # Validate the repaired code
                            f_result_r, message_r = target.validate_individual(file_name_repaired)
                            
                            # If the repair fixed the compile error:
                            if "error:" not in str(message_r).lower():
                                # SUCCESS! Swap the bad code with the good code
                                fo = repaired_code
                                f_result = f_result_r
                                message = message_r
                                
                                # Overwrite the original .fuzz file with the fixed version
                                # This ensures the dataset contains the valid code
                                write_to_file(fo, file_name)
                    # =================================================
                    
                    target.parse_validation_message(f_result, message, file_name)
                    prev.append((f_result, fo))
                else:
                    # If OTF is off, we can't validate, so we assume success for the loop
                    # But typically OTF is True in your config.
                    prev.append((None, fo))

                count += 1
                p.update(task, advance=1)
                
            target.update(prev=prev)


# evaluate against the oracle to discover any potential bugs
# used after the generation
def evaluate_all(target: Target):
    target.validate_all()


@click.group()
@click.option(
    "config_file",
    "--config",
    type=str,
    default=None,
    help="Path to the configuration file.",
)
@click.pass_context
def cli(ctx, config_file):
    """Run the main using a configuration file."""
    if config_file is not None:
        config_dict = load_config_file(config_file)
        ctx.ensure_object(dict)
        ctx.obj["CONFIG_DICT"] = config_dict


@cli.command("main_with_config")
@click.pass_context
@click.option(
    "folder",
    "--folder",
    type=str,
    default="Results/test",
    help="folder to store results",
)
@click.option(
    "cpu",
    "--cpu",
    is_flag=True,
    help="to use cpu",  # this is for GPU resource low situations where only cpu is available
)
@click.option(
    "batch_size",
    "--batch_size",
    type=int,
    default=30,
    help="batch size for the model",
)
@click.option(
    "model_name",
    "--model_name",
    type=str,
    default="bigcode/starcoderbase",
    help="model to use",
)
@click.option(
    "target",
    "--target",
    type=str,
    default="",
    help="specific target to run",
)
def main_with_config(ctx, folder, cpu, batch_size, target, model_name):
    """Run the main using a configuration file."""
    config_dict = ctx.obj["CONFIG_DICT"]
    fuzzing = config_dict["fuzzing"]
    config_dict["fuzzing"]["output_folder"] = folder
    if cpu:
        config_dict["llm"]["device"] = "cpu"
    if batch_size:
        config_dict["llm"]["batch_size"] = batch_size
    if model_name != "":
        config_dict["llm"]["model_name"] = model_name
    if target != "":
        config_dict["fuzzing"]["target_name"] = target
    print(config_dict)

    target = make_target_with_config(config_dict)
    if not fuzzing["evaluate"]:
        assert (
            not os.path.exists(folder) or fuzzing["resume"]
        ), f"{folder} already exists!"
        os.makedirs(fuzzing["output_folder"], exist_ok=True)
        fuzz(
            target=target,
            number_of_iterations=fuzzing["num"],
            total_time=fuzzing["total_time"],
            output_folder=folder,
            resume=fuzzing["resume"],
            otf=fuzzing["otf"],
        )
    else:
        evaluate_all(target)


if __name__ == "__main__":
    cli()