/**
 * Copyright Adrian Hayes 2012
 * 
 * This file is part of BurpJS.
 * BurpJS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * BurpJS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with BurpJS.  If not, see <http://www.gnu.org/licenses/>.
 */

package burp;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author adrian
 */
public class FileChangeMonitor {
    
    
    private List<MonitoredFile> filesMonitored = new ArrayList<MonitoredFile>();
    
    
    public void addFile(File file) {
        
        filesMonitored.add(new MonitoredFile(file, file.lastModified()));        
    }    
    
    
    public List<File> getChangedFiles() {
        
        List<File> changedFiles = new ArrayList<File>();
        for (MonitoredFile file : filesMonitored) 
            if (file.getFile().lastModified() != file.getModTime())
                changedFiles.add(file.getFile());
        
        return changedFiles;
        
    }
    
    public List<File> getMonitoredFiles() {
        List<File> files = new ArrayList<File>();
        for (MonitoredFile file : filesMonitored) 
               files.add(file.getFile());
        
        return files;
    }
    
    public boolean hasAnyFileChanged() {
        for (MonitoredFile file : filesMonitored) 
            if (file.getFile().lastModified() != file.getModTime())
                return true;
        
        return false;
    }
    
    
    public void resetAll() {
        for (MonitoredFile file : filesMonitored) 
            file.setModTime(file.getFile().lastModified());
    }
    
    private class MonitoredFile {
        
        private File file;
        private long modTime;

        public MonitoredFile(File file, long modTime) {
            this.file = file;
            this.modTime = modTime;
        }

        public File getFile() {
            return file;
        }

        public long getModTime() {
            return modTime;
        }

        public void setModTime(long modTime) {
            this.modTime = modTime;
        }
        
    }
}
