"""
PortRedirect Logo Generator
---------------------------
This script generates a 3D logo scene for "PortRedirect" in Blender.
It creates various scene elements including:
    - A custom skybox with textured detail to provide practical reflections for gold.
    - Background pipes and clouds to add depth.
    - A hollow green pipe with improved reflective properties.
    - Reflective gold text with subtle bump details (not in Eevee).
    - Custom lighting and camera setups.
    - A world background with a dark Mario-blue tone.

This script is intended to be run manually from the Scripting view in an empty Blender project.
"""

import bpy
import os
import random


def cleanup_scene():
    # Remove all existing objects from the scene.
    bpy.ops.object.select_all(action="SELECT")
    bpy.ops.object.delete(use_global=False)


def setup_random_seed(seed=42):
    random.seed(seed)


def create_background_pipes():
    for i in range(20):
        # Define parameters for the outer pipe
        radius = 0.5
        depth = random.uniform(4, 6)
        x = random.uniform(-8, 8)
        y = random.uniform(13, 17)  # placed in the distance
        z = random.uniform(-20, -10)

        # Create the outer cylinder
        bpy.ops.mesh.primitive_cylinder_add(
            radius=radius, depth=depth, location=(x, y, z)
        )
        outer_pipe = bpy.context.object
        outer_pipe.name = f"DimPipe_{i}"

        # Create an inner cylinder to hollow out the pipe
        inner_radius = radius - 0.15  # slightly smaller than the outer radius
        inner_depth = depth + 0.2  # slightly taller for a clean subtraction
        bpy.ops.mesh.primitive_cylinder_add(
            radius=inner_radius, depth=inner_depth, location=(x, y, z)
        )
        inner_pipe = bpy.context.object
        inner_pipe.name = f"DimPipeInner_{i}"

        # Apply a Boolean difference modifier to subtract the inner from the outer
        bool_mod = outer_pipe.modifiers.new(name="PipeHole", type="BOOLEAN")
        bool_mod.operation = "DIFFERENCE"
        bool_mod.object = inner_pipe
        bpy.context.view_layer.objects.active = outer_pipe
        bpy.ops.object.modifier_apply(modifier=bool_mod.name)

        # Delete the inner cylinder
        bpy.data.objects.remove(inner_pipe, do_unlink=True)

        # Assign a dim, off-color material to the now-hollow outer pipe
        dim_mat = bpy.data.materials.new(name=f"DimPipeMat_{i}")
        dim_mat.use_nodes = True
        dnodes = dim_mat.node_tree.nodes
        dprincipled = dnodes.get("Principled BSDF")
        dprincipled.inputs["Base Color"].default_value = (
            0.2,
            0.2,
            0.3,
            1,
        )  # dark off-color blue/grey
        dprincipled.inputs["Metallic"].default_value = 0.2
        dprincipled.inputs["Roughness"].default_value = 0.8
        outer_pipe.data.materials.append(dim_mat)


def create_clouds():
    for i in range(13):
        # Base position for the cloud
        base_x = random.uniform(-20, 20)
        base_y = random.uniform(10, 50)
        base_z = random.uniform(-30, -20)

        # Determine how many ellipses (parts) will form this cloud
        num_parts = random.randint(1, 3)
        cloud_parts = []

        for j in range(num_parts):
            # Random offset for each ellipse relative to the base position
            offset_x = random.uniform(-1.0, 1.0)
            offset_y = random.uniform(-1.0, 1.0)
            offset_z = random.uniform(-0.2, 0.2)  # slight variation in depth

            pos_x = base_x + offset_x
            pos_y = base_y + offset_y
            pos_z = base_z + offset_z

            # Create a filled ellipse (disk)
            bpy.ops.mesh.primitive_circle_add(
                vertices=32, radius=1, fill_type="NGON", location=(pos_x, pos_y, pos_z)
            )
            ellipse = bpy.context.object
            ellipse.name = f"Cloud_{i}_{j}"

            # Apply random scaling for the ellipse shape
            scale_x = random.uniform(2.0, 3.0)
            scale_y = random.uniform(1.0, 1.5)
            scale_z = random.uniform(0.3, 0.5)
            ellipse.scale = (scale_x, scale_y, scale_z)

            # Optionally, add a slight random rotation around Z for variation
            ellipse.rotation_euler[2] = random.uniform(0, 6.28319)

            # Create and assign a simple cloud material with a mix of Principled and Emission shaders
            cloud_mat = bpy.data.materials.new(name=f"CloudMaterial_{i}_{j}")
            cloud_mat.use_nodes = True
            c_nodes = cloud_mat.node_tree.nodes
            c_principled = c_nodes.get("Principled BSDF")
            c_principled.inputs["Base Color"].default_value = (0.9, 0.9, 0.9, 1)
            c_principled.inputs["Roughness"].default_value = 1.0

            # Create an Emission node for a subtle glow
            emission = c_nodes.new(type="ShaderNodeEmission")
            emission.inputs["Color"].default_value = (1, 1, 1, 1)
            emission.inputs["Strength"].default_value = 0.2

            # Mix the two shaders
            mix_shader = c_nodes.new(type="ShaderNodeMixShader")
            links = cloud_mat.node_tree.links
            links.new(c_principled.outputs["BSDF"], mix_shader.inputs[1])
            links.new(emission.outputs["Emission"], mix_shader.inputs[2])
            mix_shader.inputs["Fac"].default_value = 0.3

            output = c_nodes.get("Material Output")
            links.new(mix_shader.outputs["Shader"], output.inputs["Surface"])

            ellipse.data.materials.append(cloud_mat)
            cloud_parts.append(ellipse)

        # Optionally join the parts so each cloud is a single object
        if len(cloud_parts) > 1:
            bpy.context.view_layer.objects.active = cloud_parts[0]
            for obj in cloud_parts:
                obj.select_set(True)
            bpy.ops.object.join()
            cloud_parts[0].name = f"Cloud_{i}"


def create_hollow_pipe():
    # Create outer cylinder
    bpy.ops.mesh.primitive_cylinder_add(radius=1, depth=5, location=(0, 0, 0))
    outer_pipe = bpy.context.object
    outer_pipe.name = "OuterPipe"

    # Create inner cylinder (slightly smaller and taller for a clean boolean)
    bpy.ops.mesh.primitive_cylinder_add(radius=0.8, depth=5.1, location=(0, 0, 0))
    inner_pipe = bpy.context.object
    inner_pipe.name = "InnerPipe"

    # Subtract inner_pipe from outer_pipe via Boolean modifier
    bool_mod = outer_pipe.modifiers.new(name="PipeHole", type="BOOLEAN")
    bool_mod.operation = "DIFFERENCE"
    bool_mod.object = inner_pipe
    bpy.context.view_layer.objects.active = outer_pipe
    bpy.ops.object.modifier_apply(modifier=bool_mod.name)

    bpy.data.objects.remove(inner_pipe, do_unlink=True)
    return outer_pipe


def assign_pipe_material(pipe):
    pipe_mat = bpy.data.materials.new(name="PipeMaterial")
    pipe_mat.use_nodes = True
    nodes = pipe_mat.node_tree.nodes
    principled = nodes.get("Principled BSDF")
    # Set a bright Mario-like green
    principled.inputs["Base Color"].default_value = (0.0, 0.6, 0.0, 1)
    # Increase metallic value to tint reflections with the green base color.
    principled.inputs["Metallic"].default_value = 0.3
    principled.inputs["Roughness"].default_value = 0.2
    pipe.data.materials.append(pipe_mat)


def create_text():
    bpy.ops.object.text_add(location=(0, -1.5, 1))
    text_obj = bpy.context.object
    text_obj.name = "LogoText"
    text_data = text_obj.data
    text_data.body = "PortRedirect"
    text_data.align_x = "CENTER"
    text_data.align_y = "CENTER"
    text_data.extrude = 0.15
    text_data.size = 1.6
    # Set a custom font: https://fonts.google.com/specimen/Oleo+Script+Swash+Caps
    font_path = os.path.join(
        os.path.expanduser("~"), "Library", "Fonts", "OleoScriptSwashCaps-Regular.ttf"
    )
    if os.path.exists(font_path):
        text_data.font = bpy.data.fonts.load(font_path)
    bpy.ops.object.convert(target="MESH")
    return bpy.context.object


def assign_text_material(text_obj):
    text_mat = bpy.data.materials.new(name="TextMaterial")
    text_mat.use_nodes = True
    nodes = text_mat.node_tree.nodes
    links = text_mat.node_tree.links

    # Get the Principled BSDF node (default in a new material)
    principled = nodes.get("Principled BSDF")

    # Set a reflective gold color (Mario title screen gold, hex #FFD700)
    principled.inputs["Base Color"].default_value = (1.0, 0.84, 0.0, 1)
    principled.inputs["Metallic"].default_value = 0.7
    principled.inputs["Roughness"].default_value = 0.1

    # Create a noise texture to drive a bump node for subtle surface details.
    noise_tex = nodes.new(type="ShaderNodeTexNoise")
    noise_tex.inputs["Scale"].default_value = 200.0  # Higher scale for finer details
    noise_tex.inputs["Detail"].default_value = 16.0

    # Create a bump node to add subtle imperfections.
    bump_node = nodes.new(type="ShaderNodeBump")
    bump_node.inputs["Strength"].default_value = 0.05  # Adjust for subtle variation

    # Connect the noise texture to the bump node and then to the Principled BSDF.
    links.new(noise_tex.outputs["Fac"], bump_node.inputs["Height"])
    links.new(bump_node.outputs["Normal"], principled.inputs["Normal"])

    # Assign the material to the text object.
    text_obj.data.materials.append(text_mat)


def create_skybox():
    # Create a large cube to act as a skybox (actually a plane in this case)
    bpy.ops.mesh.primitive_cube_add(location=(0, 0, 50))
    skybox = bpy.context.object
    skybox.name = "Skybox"
    # Scale up the cube so it forms a large plane behind the camera
    skybox.scale = (100, 100, 1)

    # Flip the normals so the inside faces are rendered
    bpy.ops.object.mode_set(mode="EDIT")
    bpy.ops.mesh.select_all(action="SELECT")
    bpy.ops.mesh.flip_normals()
    bpy.ops.object.mode_set(mode="OBJECT")

    # Create an unlit material for the skybox using an Emission shader
    skybox_mat = bpy.data.materials.new(name="SkyboxMaterial")
    skybox_mat.use_nodes = True
    nodes = skybox_mat.node_tree.nodes
    links = skybox_mat.node_tree.links

    # Clear all existing nodes
    for node in nodes:
        nodes.remove(node)

    # Create an Emission node (this will be our final shader)
    emission_node = nodes.new(type="ShaderNodeEmission")
    emission_node.location = (400, 0)
    emission_node.inputs["Strength"].default_value = 1.0

    # Create a Noise Texture node for texture detail
    noise_node = nodes.new(type="ShaderNodeTexNoise")
    noise_node.location = (-600, 0)
    noise_node.inputs["Scale"].default_value = 20.0
    noise_node.inputs["Detail"].default_value = 2.0

    # Create a ColorRamp to map noise values to colors simulating leaves on a wood-like background
    color_ramp = nodes.new(type="ShaderNodeValToRGB")
    color_ramp.location = (-400, 0)
    # Set left stop (most of the area) to a light grey (wood-like base)
    color_ramp.color_ramp.elements[0].position = 0.4
    color_ramp.color_ramp.elements[0].color = (0.8, 0.8, 0.8, 1)
    # Set right stop to a dark green to simulate sparse leaves
    color_ramp.color_ramp.elements[1].position = 0.6
    color_ramp.color_ramp.elements[1].color = (0.0, 0.3, 0.0, 1)

    # Create a MixRGB node to blend our base sky-blue with the noise-driven pattern
    mix_node = nodes.new(type="ShaderNodeMixRGB")
    mix_node.location = (0, 0)
    mix_node.blend_type = "MIX"
    # Color1: the base sky-blue color
    mix_node.inputs["Color1"].default_value = (0.6, 0.8, 1.0, 1)
    # Adjust Fac to control how strongly the noise pattern shows through
    mix_node.inputs["Fac"].default_value = 0.3

    # Create the Material Output node
    output_node = nodes.new(type="ShaderNodeOutputMaterial")
    output_node.location = (600, 0)

    # Connect nodes:
    # Noise -> ColorRamp
    links.new(noise_node.outputs["Fac"], color_ramp.inputs["Fac"])
    # ColorRamp -> MixRGB Color2
    links.new(color_ramp.outputs["Color"], mix_node.inputs["Color2"])
    # MixRGB -> Emission Color
    links.new(mix_node.outputs["Color"], emission_node.inputs["Color"])
    # Emission -> Material Output
    links.new(emission_node.outputs["Emission"], output_node.inputs["Surface"])

    # Note: In Eevee, Screen Space Reflections (SSR) may not fully capture these detailed textures.
    # In the shader view this skybox looks great, but the final render might not display the detail
    # until Eevee improves or SSR settings are adjusted.

    # Assign the material to the skybox object
    skybox.data.materials.append(skybox_mat)


def setup_lighting():
    # Create an Area Light with increased energy
    bpy.ops.object.light_add(type="AREA", location=(0, 0, 10))
    light_area = bpy.context.object
    light_area.data.energy = 2000
    light_area.data.size = 100

    # Create an Area Light around the Text with increased energy
    bpy.ops.object.light_add(type="AREA", location=(0, -5, 3))
    light_area = bpy.context.object
    light_area.data.energy = 100
    light_area.data.size = 10
    # and below it
    bpy.ops.object.light_add(type="AREA", location=(0, -5, -3))
    light_area = bpy.context.object
    light_area.data.energy = 50
    light_area.data.size = 10

    # Left text highlight spot
    bpy.ops.object.light_add(type="AREA", location=(-2, -1.5, 2))
    light_area = bpy.context.object
    light_area.data.energy = 30
    light_area.data.size = 5

    # Right text highlight spot
    bpy.ops.object.light_add(type="AREA", location=(2, -1.5, 2))
    light_area = bpy.context.object
    light_area.data.energy = 50
    light_area.data.size = 5

    # Create a Point Light with increased energy
    bpy.ops.object.light_add(type="POINT", location=(-20, -7, 10))
    light_point = bpy.context.object
    light_point.data.energy = 9000


def setup_camera():
    bpy.ops.object.camera_add(location=(0, -10, 10))
    camera = bpy.context.object
    camera.rotation_euler = (0.785, 0, 0)  # 45° downward tilt
    bpy.context.scene.camera = camera


def setup_world_background():
    if bpy.data.worlds:
        world = bpy.data.worlds[0]
    else:
        world = bpy.data.worlds.new("World")
    bpy.context.scene.world = world
    world.use_nodes = True
    bg_node = world.node_tree.nodes.get("Background")
    if bg_node:
        # Slightly darker Mario Blue (hex #2D70B3 => (0.18, 0.44, 0.70, 1))
        bg_node.inputs[0].default_value = (0.18, 0.44, 0.70, 1)
        bg_node.inputs[1].default_value = (
            0.2  # Increase the strength for more ambient light
        )
    else:
        raise Exception("i need a Background node")


def setup_render_settings(output_path):
    scene = bpy.context.scene
    scene.render.engine = "BLENDER_EEVEE_NEXT"

    scene.view_settings.view_transform = "Filmic"
    scene.view_settings.look = "None"
    scene.view_settings.exposure = 1.2

    scene.render.resolution_x = 1920
    scene.render.resolution_y = 1080
    scene.render.image_settings.file_format = "PNG"
    scene.render.filepath = output_path


def main():
    cleanup_scene()
    setup_random_seed(42)
    create_skybox()
    create_background_pipes()
    create_clouds()
    pipe = create_hollow_pipe()
    assign_pipe_material(pipe)
    logo_text = create_text()
    assign_text_material(logo_text)
    setup_lighting()
    setup_camera()
    setup_world_background()
    output_path = os.path.join(bpy.path.abspath("//"), "portredirect_logo.png")
    setup_render_settings(output_path)

    bpy.ops.render.render(write_still=True)
    print("Logo rendered and saved to", output_path)


main()
