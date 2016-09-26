begin
  require 'puppet_x/bodeco/archive'
  require 'puppet_x/bodeco/util'
  require 'puppet/util/resource_template'
rescue LoadError
  require 'pathname' # WORK_AROUND #14073 and #7788
  archive = Puppet::Module.find('archive', Puppet[:environment].to_s)
  raise(LoadError, "Unable to find archive module in modulepath #{Puppet[:basemodulepath] || Puppet[:modulepath]}") unless archive
  require File.join archive.path, 'lib/puppet_x/bodeco/archive'
  require File.join archive.path, 'lib/puppet_x/bodeco/util'
end

require 'securerandom'
require 'tempfile'
require 'puppet/util'
require 'puppet/node/facts'

Puppet::Type.type(:archive).provide(:ruby) do
  include Puppet::Util::Diff

  optional_commands aws: 'aws'
  defaultfor feature: :microsoft_windows
  attr_reader :archive_checksum

  def exists?
    if extracted?
      if File.exist? archive_filepath
        checksum?
      else
        cleanup
        true
      end
    else
      checksum?
    end
  end

  def create
    transfer_download(archive_filepath) unless checksum?
    extract
    cleanup
  end

  def destroy
    FileUtils.rm_f(archive_filepath) if File.exist?(archive_filepath)
  end

  def archive_filepath
    resource[:path]
  end

  def tempfile_name
    if resource[:checksum] == 'none'
      "#{resource[:filename]}_#{SecureRandom.base64}"
    else
      "#{resource[:filename]}_#{resource[:checksum]}"
    end
  end

  def creates
    if resource[:extract] == :true
      extracted? ? resource[:creates] : 'archive not extracted'
    else
      resource[:creates]
    end
  end

  def creates=(_value)
    extract
  end

  def checksum
    resource[:checksum] || (resource[:checksum] = remote_checksum if resource[:checksum_url])
  end

  def remote_checksum
    PuppetX::Bodeco::Util.content(
      resource[:checksum_url],
      username: resource[:username],
      password: resource[:password],
      cookie: resource[:cookie],
      proxy_server: resource[:proxy_server],
      proxy_type: resource[:proxy_type],
      insecure: resource[:allow_insecure]
    )[%r{\b[\da-f]{32,128}\b}i]
  end

  # Private: See if local archive checksum matches.
  # returns boolean
  def checksum?(store_checksum = true)
    archive_exist = File.exist? archive_filepath
    if archive_exist && resource[:checksum_type] != :none
      archive = PuppetX::Bodeco::Archive.new(archive_filepath)
      archive_checksum = archive.checksum(resource[:checksum_type])
      @archive_checksum = archive_checksum if store_checksum
      checksum == archive_checksum
    else
      archive_exist
    end
  end

  def cleanup
    return unless extracted? && resource[:cleanup] == :true
    Puppet.debug("Cleanup archive #{archive_filepath}")
    destroy
  end

  def extract
    Puppet.debug('WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW')
    return unless resource[:extract] == :true
    raise(ArgumentError, 'missing archive extract_path') unless resource[:extract_path]

    remove_tmp_folder = false

    extract_path = resource[:extract_path]



    if Puppet[:show_diff] and resource[:show_diff]
      #  write_temporarily do |path|
      #    send @resource[:loglevel], "\n" + diff(@resource[:path], path)
      #  end
      o = [('a'..'z'), ('A'..'Z')].map { |i| i.to_a }.flatten
      tmp_folder = '/tmp/' + (0...50).map { o[rand(o.length)] }.join
      remove_tmp_folder = true

      FileUtils.mkdir_p(tmp_folder)
      PuppetX::Bodeco::Archive.new(archive_filepath).extract(
        tmp_folder,
        :custom_command => resource[:extract_command],
        :options => resource[:extract_flags],
        :uid => resource[:user],
        :gid => resource[:group]
      )
      Puppet.debug('Extracted archive to temporary location ' + tmp_folder)
      #Puppet.debug(diff(tmp_folder + '/content/overlay.js', resource[:extract_path] + '/content/overlay.js'))

      # Since we do call Facter after compilation, it will be generated again, hence
      # need to limit calls
      facts = Facter.to_hash

      #Puppet.debug(diff_dirs(tmp_folder, resource[:extract_path]))
      Dir.chdir(tmp_folder) do
        # !!!!!! TO BE UPDATED TO HANDLE NEW FILES AND FOLDERS
        Dir.glob("**/*").select {|file| !File.directory? file}.each { |file|
          ##if (Dir.exists(extract_path + "/" + file))
          if File.extname(file) == ".erb"
            Puppet.debug("Found template " + file)

            # Removes erb extension and untemplate
            generated_file = File.join(File.dirname(File.absolute_path(file)), File.basename(file, ".erb"))
            content = Puppet::Util::ResourceTemplate.new(file, facts).evaluate
            File.open(generated_file, 'w') { |file| file.write(content) }

            existing_generated_file = File.join(File.dirname(file), File.basename(file, "*.erb"))

            # output diff of un-templated file
            Puppet.debug(diff(generated_file, existing_generated_file))

            # Cleanup after run so we don't copy erb files
            File.delete(file)
          else
            Puppet.debug(diff(tmp_folder + "/" + file, extract_path + "/" + file))
          end
        }
        end
      end

      if ! Puppet[:noop]
        FileUtils.cp_r(tmp_folder + "/.", extract_path)
        # Copy or extract files only if noop not globally specified
        # PuppetX::Bodeco::Archive.new(archive_filepath).extract(
        #   resource[:extract_path],
        #   :custom_command => resource[:extract_command],
        #   :options => resource[:extract_flags],
        #   :uid => resource[:user],
        #   :gid => resource[:group]
        # )
      end

      # Cleanup after show_diff
      if remove_tmp_folder && File.directory?(tmp_folder) then
        FileUtils.rm_rf(tmp_folder)
      end

  end

  def extracted?
    resource[:creates] && File.exist?(resource[:creates])
  end

  def transfer_download(archive_filepath)
    tempfile = Tempfile.new(tempfile_name)
    temppath = tempfile.path
    tempfile.close!

    case resource[:source]
    when %r{^(http|ftp)}
      download(temppath)
    when %r{^file}
      uri = URI(resource[:source])
      FileUtils.copy(Puppet::Util.uri_to_path(uri), temppath)
    when %r{^s3}
      s3_download(temppath)
    when nil
      raise(Puppet::Error, 'Unable to fetch archive, the source parameter is nil.')
    else
      raise(Puppet::Error, "Source file: #{resource[:source]} does not exists.") unless File.exist?(resource[:source])
      FileUtils.copy(resource[:source], temppath)
    end

    # conditionally verify checksum:
    if resource[:checksum_verify] == :true && resource[:checksum_type] != :none
      archive = PuppetX::Bodeco::Archive.new(temppath)
      raise(Puppet::Error, 'Download file checksum mismatch') unless archive.checksum(resource[:checksum_type]) == checksum
    end

    FileUtils.mkdir_p(File.dirname(archive_filepath))
    FileUtils.mv(temppath, archive_filepath)
  end

  def download(filepath)
    PuppetX::Bodeco::Util.download(
      resource[:source],
      filepath,
      username: resource[:username],
      password: resource[:password],
      cookie: resource[:cookie],
      proxy_server: resource[:proxy_server],
      proxy_type: resource[:proxy_type],
      insecure: resource[:allow_insecure]
    )
  end

  def s3_download(path)
    params = [
      's3',
      'cp',
      resource[:source],
      path
    ]

    aws(params)
  end

  def optional_switch(value, option)
    if value
      option.map { |flags| flags % value }
    else
      []
    end
  end
end
