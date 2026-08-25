#!/usr/bin/env ruby
# frozen_string_literal: true

require "psych"

DEFAULT_WORKFLOWS = [
  ".github/workflows/publish.yml",
  ".github/workflows/publish-npm.yml"
].freeze
FULL_COMMIT_SHA = /\A[0-9a-fA-F]{40}\z/.freeze
DOCKER_DIGEST = /\Adocker:\/\/[^@\s]+@sha256:[0-9a-fA-F]{64}\z/.freeze

def annotation(file, node, message)
  line = node.respond_to?(:start_line) ? node.start_line + 1 : 1
  warn "::error file=#{file},line=#{line}::#{message}"
end

def validate_reference(file, key_node, value_node)
  unless value_node.is_a?(Psych::Nodes::Scalar)
    annotation(file, key_node, "publishing action reference must be a scalar")
    return false
  end

  reference = value_node.value
  if reference.start_with?("./")
    annotation(
      file,
      value_node,
      "repository-local actions are forbidden in publishing workflows: #{reference}"
    )
    return false
  end

  if reference.start_with?("docker://")
    return true if DOCKER_DIGEST.match?(reference)

    annotation(
      file,
      value_node,
      "publishing docker action must use a sha256 digest: #{reference}"
    )
    return false
  end

  action, separator, revision = reference.rpartition("@")
  return true if separator == "@" && action.include?("/") && FULL_COMMIT_SHA.match?(revision)

  annotation(
    file,
    value_node,
    "publishing action must use a full commit SHA: #{reference}"
  )
  false
end

def inspect_node(file, node, state)
  if node.is_a?(Psych::Nodes::Alias)
    annotation(file, node, "YAML aliases are forbidden in publishing workflows")
    state[:valid] = false
    return
  end

  if node.is_a?(Psych::Nodes::Mapping)
    node.children.each_slice(2) do |key_node, value_node|
      if key_node.is_a?(Psych::Nodes::Scalar) && key_node.value == "uses"
        state[:uses] += 1
        state[:valid] = false unless validate_reference(file, key_node, value_node)
      end
      inspect_node(file, key_node, state)
      inspect_node(file, value_node, state)
    end
    return
  end

  return unless node.respond_to?(:children)

  children = node.children
  return unless children

  children.each { |child| inspect_node(file, child, state) }
end

workflow_files = ARGV.empty? ? DEFAULT_WORKFLOWS : ARGV
valid = true
references = 0

workflow_files.each do |file|
  begin
    document = Psych.parse_file(file)
    unless document
      warn "::error file=#{file}::publishing workflow YAML is empty"
      valid = false
      next
    end

    state = { valid: true, uses: 0 }
    inspect_node(file, document, state)
    valid &&= state[:valid]
    references += state[:uses]
  rescue Errno::ENOENT, Errno::EACCES => error
    warn "::error file=#{file}::publishing workflow cannot be read: #{error.message}"
    valid = false
  rescue Psych::SyntaxError => error
    warn "::error file=#{file},line=#{error.line}::invalid publishing workflow YAML: #{error.problem}"
    valid = false
  end
end

exit 1 unless valid

puts "Publishing workflow actions are structurally parsed and pinned " \
     "to immutable revisions (#{references} references)."
