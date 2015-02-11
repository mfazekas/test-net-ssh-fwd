class ScpInputOutputFilter
  # see 
  #  https://github.com/net-ssh/net-scp/blob/master/lib/net/scp.rb
  def initialize(command,options={})
    @buffer = ""
    args = command.split(' ')
    raise "Command should be scp but was #{args[0]}" unless args.shift == 'scp'
    params = args.take_while { |i| i =~ /^-[a-zA-Z]$/ }
    if params.include?('-t')
      @mode = :upload_start_state
    elsif params.include?('-d')
      @mode = :download_start_state
    else
      raise "Unexpected #{@mode}"
    end
  end

  # this is for override
  def handle_c_directive(line)
    nil
  end

  def read_until(separator)
    if (i = @buffer.index(separator)) != nil
      ret = @buffer[0..i]
      @buffer = @buffer[i+1..-1]
      ret
    end
  end

  def filterin(data)
    case @mode
    when :upload_current_state
      @buffer+=data
      if line = read_until("\n")
        if line[0] == 'C'
          @mode = :upload_current_state_end
          return handle_c_directive(line)
        end
      end
    end
    nil
  end

  def filterout(data)
    @mode = case @mode
      when :upload_start_state
        :upload_current_state
      when :upload_current_state
        :upload_current_state
      when :upload_current_state_end
        :send_data_state
      when :send_data_state
        :upload_current_state
    end
    @buffer = ''
    nil
  end

end
